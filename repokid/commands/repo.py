#     Copyright 2020 Netflix, Inc.
#
#     Licensed under the Apache License, Version 2.0 (the "License");
#     you may not use this file except in compliance with the License.
#     You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS,
#     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#     See the License for the specific language governing permissions and
#     limitations under the License.
import csv
import datetime
import json
import logging
import pprint
import time

import botocore
from cloudaux.aws.iam import (
    delete_role_policy,
    get_role_inline_policies,
    put_role_policy,
)
import repokid.hooks
from repokid.role import Role, Roles
from repokid.utils import roledata as roledata
from repokid.utils.dynamo import (
    find_role_in_cache,
    get_role_data,
    role_ids_for_account,
    role_ids_for_all_accounts,
    set_role_data,
)
from repokid.utils.iam import (
    delete_policy,
    inline_policies_size_exceeds_maximum,
    replace_policies,
    update_repoed_description,
)
from repokid.utils.logging import log_deleted_and_repoed_policies
from repokid.utils.roledata import partial_update_role_data
from tabulate import tabulate

LOGGER = logging.getLogger("repokid")


def _repo_role(
    account_number,
    role_name,
    dynamo_table,
    config,
    hooks,
    commit=False,
    scheduled=False,
):
    """
    Calculate what repoing can be done for a role and then actually do it if commit is set
      1) Check that a role exists, it isn't being disqualified by a filter, and that is has fresh AA data
      2) Get the role's current permissions, repoable permissions, and the new policy if it will change
      3) Make the changes if commit is set
    Args:
        account_number (string)
        role_name (string)
        commit (bool)

    Returns:
        None
    """
    errors = []

    role_id = find_role_in_cache(dynamo_table, account_number, role_name)
    # only load partial data that we need to determine if we should keep going
    role_data = get_role_data(
        dynamo_table,
        role_id,
        fields=["DisqualifiedBy", "AAData", "RepoablePermissions", "RoleName"],
    )
    if not role_data:
        LOGGER.warn("Could not find role with name {}".format(role_name))
        return
    else:
        role = Role(role_data)

    continuing = True

    if len(role.disqualified_by) > 0:
        LOGGER.info(
            "Cannot repo role {} in account {} because it is being disqualified by: {}".format(
                role_name, account_number, role.disqualified_by
            )
        )
        continuing = False

    if not role.aa_data:
        LOGGER.warning("ARN not found in Access Advisor: {}".format(role.arn))
        continuing = False

    if not role.repoable_permissions:
        LOGGER.info(
            "No permissions to repo for role {} in account {}".format(
                role_name, account_number
            )
        )
        continuing = False

    # if we've gotten to this point, load the rest of the role
    role = Role(get_role_data(dynamo_table, role_id))

    old_aa_data_services = []
    for aa_service in role.aa_data:
        if datetime.datetime.strptime(
            aa_service["lastUpdated"], "%a, %d %b %Y %H:%M:%S %Z"
        ) < datetime.datetime.now() - datetime.timedelta(
            days=config["repo_requirements"]["oldest_aa_data_days"]
        ):
            old_aa_data_services.append(aa_service["serviceName"])

    if old_aa_data_services:
        LOGGER.error(
            "AAData older than threshold for these services: {} (role: {}, account {})".format(
                old_aa_data_services, role_name, account_number
            ),
            exc_info=True,
        )
        continuing = False

    total_permissions, eligible_permissions = roledata._get_role_permissions(role)
    repoable_permissions = roledata._get_repoable_permissions(
        account_number,
        role.role_name,
        eligible_permissions,
        role.aa_data,
        role.no_repo_permissions,
        config["filter_config"]["AgeFilter"]["minimum_age"],
        hooks,
    )

    # if this is a scheduled repo we need to filter out permissions that weren't previously scheduled
    if scheduled:
        repoable_permissions = roledata._filter_scheduled_repoable_perms(
            repoable_permissions, role.scheduled_perms
        )

    repoed_policies, deleted_policy_names = roledata._get_repoed_policy(
        role.policies[-1]["Policy"], repoable_permissions
    )

    if inline_policies_size_exceeds_maximum(repoed_policies):
        error = (
            "Policies would exceed the AWS size limit after repo for role: {} in account {}.  "
            "Please manually minify.".format(role_name, account_number)
        )
        LOGGER.error(error)
        errors.append(error)
        continuing = False

    # if we aren't repoing for some reason, unschedule the role
    if not continuing:
        set_role_data(
            dynamo_table, role.role_id, {"RepoScheduled": 0, "ScheduledPerms": []}
        )
        return

    if not commit:
        log_deleted_and_repoed_policies(
            deleted_policy_names, repoed_policies, role_name, account_number
        )
        return

    conn = config["connection_iam"]
    conn["account_number"] = account_number

    for name in deleted_policy_names:
        error = delete_policy(name, role, account_number, conn)
        if error:
            LOGGER.error(error)
            errors.append(error)

    if repoed_policies:
        error = replace_policies(repoed_policies, role, account_number, conn)
        if error:
            LOGGER.error(error)
            errors.append(error)

    current_policies = get_role_inline_policies(role.as_dict(), **conn) or {}
    roledata.add_new_policy_version(dynamo_table, role, current_policies, "Repo")

    # regardless of whether we're successful we want to unschedule the repo
    set_role_data(
        dynamo_table, role.role_id, {"RepoScheduled": 0, "ScheduledPerms": []}
    )

    repokid.hooks.call_hooks(hooks, "AFTER_REPO", {"role": role, "errors": errors})

    if not errors:
        # repos will stay scheduled until they are successful
        set_role_data(
            dynamo_table,
            role.role_id,
            {"Repoed": datetime.datetime.utcnow().isoformat()},
        )
        update_repoed_description(role.role_name, **conn)
        partial_update_role_data(
            role,
            dynamo_table,
            account_number,
            config,
            conn,
            hooks,
            source="Repo",
            add_no_repo=False,
        )
        LOGGER.info(
            "Successfully repoed role: {} in account {}".format(
                role.role_name, account_number
            )
        )
    return errors


def _rollback_role(
    account_number, role_name, dynamo_table, config, hooks, selection=None, commit=None
):
    """
    Display the historical policy versions for a roll as a numbered list.  Restore to a specific version if selected.
    Indicate changes that will be made and then actually make them if commit is selected.

    Args:
        account_number (string)
        role_name (string)
        selection (int): which policy version in the list to rollback to
        commit (bool): actually make the change

    Returns:
        errors (list): if any
    """
    errors = []

    role_id = find_role_in_cache(dynamo_table, account_number, role_name)
    if not role_id:
        message = "Could not find role with name {} in account {}".format(
            role_name, account_number
        )
        errors.append(message)
        LOGGER.warning(message)
        return errors
    else:
        role = Role(get_role_data(dynamo_table, role_id))

    # no option selected, display a table of options
    if not selection:
        headers = ["Number", "Source", "Discovered", "Permissions", "Services"]
        rows = []
        for index, policies_version in enumerate(role.policies):
            policy_permissions, _ = roledata._get_permissions_in_policy(
                policies_version["Policy"]
            )
            rows.append(
                [
                    index,
                    policies_version["Source"],
                    policies_version["Discovered"],
                    len(policy_permissions),
                    roledata._get_services_in_permissions(policy_permissions),
                ]
            )
        print(tabulate(rows, headers=headers))
        return

    conn = config["connection_iam"]
    conn["account_number"] = account_number

    current_policies = get_role_inline_policies(role.as_dict(), **conn)

    if selection:
        pp = pprint.PrettyPrinter()

        print("Will restore the following policies:")
        pp.pprint(role.policies[int(selection)]["Policy"])

        print("Current policies:")
        pp.pprint(current_policies)

        current_permissions, _ = roledata._get_permissions_in_policy(
            role.policies[-1]["Policy"]
        )
        selected_permissions, _ = roledata._get_permissions_in_policy(
            role.policies[int(selection)]["Policy"]
        )
        restored_permissions = selected_permissions - current_permissions

        print("\nResore will return these permissions:")
        print("\n".join([perm for perm in sorted(restored_permissions)]))

    if not commit:
        return False

    # if we're restoring from a version with fewer policies than we have now, we need to remove them to
    # complete the restore.  To do so we'll store all the policy names we currently have and remove them
    # from the list as we update.  Any policy names left need to be manually removed
    policies_to_remove = current_policies.keys()

    for policy_name, policy in role.policies[int(selection)]["Policy"].items():
        try:
            LOGGER.info(
                f"Pushing cached policy: {policy_name} (role: {role.role_name} account {account_number})"
            )

            put_role_policy(
                RoleName=role.role_name,
                PolicyName=policy_name,
                PolicyDocument=json.dumps(policy, indent=2, sort_keys=True),
                **conn,
            )

        except botocore.exceptions.ClientError as e:
            message = "Unable to push policy {}.  Error: {} (role: {} account {})".format(
                policy_name, e.message, role.role_name, account_number
            )
            LOGGER.error(message, exc_info=True)
            errors.append(message)

        else:
            # remove the policy name if it's in the list
            try:
                policies_to_remove.remove(policy_name)
            except Exception:  # nosec
                pass

    if policies_to_remove:
        for policy_name in policies_to_remove:
            try:
                LOGGER.info(
                    f"Deleting policy {policy_name} for rollback (role: {role.role_name} account {account_number})"
                )
                delete_role_policy(
                    RoleName=role.role_name, PolicyName=policy_name, **conn
                )

            except botocore.excpetions.ClientError as e:
                message = "Unable to delete policy {}.  Error: {} (role: {} account {})".format(
                    policy_name, e.message, role.role_name, account_number
                )
                LOGGER.error(message, exc_info=True)
                errors.append(message)

    partial_update_role_data(
        role,
        dynamo_table,
        account_number,
        config,
        conn,
        hooks,
        source="Restore",
        add_no_repo=False,
    )

    if not errors:
        LOGGER.info(
            f"Successfully restored selected version {selection} of role policies (role: {role.role_name} "
            f"account: {account_number}"
        )
    return errors


def _repo_all_roles(
    account_number, dynamo_table, config, hooks, commit=False, scheduled=True, limit=-1
):
    """
    Repo all scheduled or eligible roles in an account.  Collect any errors and display them at the end.

    Args:
        account_number (string)
        dynamo_table
        config
        commit (bool): actually make the changes
        scheduled (bool): if True only repo the scheduled roles, if False repo all the (eligible) roles
        limit (int): limit number of roles to be repoed per run (< 0 is unlimited)

    Returns:
        None
    """
    errors = []

    role_ids_in_account = role_ids_for_account(dynamo_table, account_number)
    roles = Roles([])
    for role_id in role_ids_in_account:
        roles.append(
            Role(
                get_role_data(
                    dynamo_table,
                    role_id,
                    fields=["Active", "RoleName", "RepoScheduled"],
                )
            )
        )

    roles = roles.filter(active=True)

    cur_time = int(time.time())

    if scheduled:
        roles = [
            role
            for role in roles
            if (role.repo_scheduled and cur_time > role.repo_scheduled)
        ]

    LOGGER.info(
        "Repoing these {}roles from account {}:\n\t{}".format(
            "scheduled " if scheduled else "",
            account_number,
            ", ".join([role.role_name for role in roles]),
        )
    )

    repokid.hooks.call_hooks(
        hooks, "BEFORE_REPO_ROLES", {"account_number": account_number, "roles": roles}
    )

    count = 0
    repoed = Roles([])
    for role in roles:
        if limit >= 0 and count == limit:
            break
        error = _repo_role(
            account_number,
            role.role_name,
            dynamo_table,
            config,
            hooks,
            commit=commit,
            scheduled=scheduled,
        )
        if error:
            errors.append(error)
        repoed.append(role)
        count += 1

    if errors:
        LOGGER.error(f"Error(s) during repo: \n{errors} (account: {account_number})")
    else:
        LOGGER.info(f"Successfully repoed {count} roles in account {account_number}")

    repokid.hooks.call_hooks(
        hooks,
        "AFTER_REPO_ROLES",
        {"account_number": account_number, "roles": repoed, "errors": errors},
    )


def _repo_stats(output_file, dynamo_table, account_number=None):
    """
    Create a csv file with stats about roles, total permissions, and applicable filters over time

    Args:
        output_file (string): the name of the csv file to write
        account_number (string): if specified only display roles from selected account, otherwise display all

    Returns:
        None
    """
    roleIDs = (
        role_ids_for_account(dynamo_table, account_number)
        if account_number
        else role_ids_for_all_accounts(dynamo_table)
    )
    headers = [
        "RoleId",
        "Role Name",
        "Account",
        "Active",
        "Date",
        "Source",
        "Permissions Count",
        "Repoable Permissions Count",
        "Disqualified By",
    ]
    rows = []

    for roleID in roleIDs:
        role_data = get_role_data(
            dynamo_table,
            roleID,
            fields=["RoleId", "RoleName", "Account", "Active", "Stats"],
        )
        for stats_entry in role_data.get("Stats", []):
            rows.append(
                [
                    role_data["RoleId"],
                    role_data["RoleName"],
                    role_data["Account"],
                    role_data["Active"],
                    stats_entry["Date"],
                    stats_entry["Source"],
                    stats_entry["PermissionsCount"],
                    stats_entry.get("RepoablePermissionsCount"),
                    stats_entry.get("DisqualifiedBy", []),
                ]
            )

    try:
        with open(output_file, "w") as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(headers)
            for row in rows:
                csv_writer.writerow(row)
    except IOError as e:
        LOGGER.error(
            "Unable to write file {}: {}".format(output_file, e), exc_info=True
        )
    else:
        LOGGER.info("Successfully wrote stats to {}".format(output_file))
