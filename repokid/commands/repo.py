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
from typing import List

import botocore
from cloudaux.aws.iam import delete_role_policy
from cloudaux.aws.iam import get_role_inline_policies
from cloudaux.aws.iam import put_role_policy
from mypy_boto3_dynamodb.service_resource import Table
from tabulate import tabulate

import repokid.hooks
from repokid.exceptions import IAMError
from repokid.role import RoleList
from repokid.types import RepokidConfig
from repokid.types import RepokidHooks
from repokid.utils import roledata as roledata
from repokid.utils.dynamo import find_role_in_cache
from repokid.utils.dynamo import get_role_data
from repokid.utils.dynamo import role_ids_for_account
from repokid.utils.dynamo import role_ids_for_all_accounts
from repokid.utils.dynamo import set_role_data
from repokid.utils.iam import delete_policy
from repokid.utils.iam import inline_policies_size_exceeds_maximum
from repokid.utils.iam import replace_policies
from repokid.utils.iam import update_repoed_description
from repokid.utils.logging import log_deleted_and_repoed_policies
from repokid.utils.roledata import partial_update_role_data

LOGGER = logging.getLogger("repokid")


def _repo_role(
    account_number: str,
    role_name: str,
    dynamo_table: Table,
    config: RepokidConfig,
    hooks: RepokidHooks,
    commit: bool = False,
    scheduled: bool = False,
) -> List[str]:
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
    errors: List[str] = []

    role_id = find_role_in_cache(dynamo_table, account_number, role_name)
    # only load partial data that we need to determine if we should keep going
    role = get_role_data(
        dynamo_table,
        role_id,
        fields=["DisqualifiedBy", "AAData", "RepoablePermissions", "RoleName"],
    )

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
    role = get_role_data(dynamo_table, role_id)

    old_aa_data_services = []
    if role.aa_data:
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
    repoable_permissions_list = roledata._get_repoable_permissions(
        account_number,
        role.role_name,
        eligible_permissions,
        role.aa_data or [],
        role.no_repo_permissions,
        role.role_id,
        config["filter_config"]["AgeFilter"]["minimum_age"],
        hooks,
    )

    repoable_permissions = set(repoable_permissions_list)

    # if this is a scheduled repo we need to filter out permissions that weren't previously scheduled
    if scheduled:
        repoable_permissions_filtered = roledata._filter_scheduled_repoable_perms(
            repoable_permissions, role.scheduled_perms
        )
        repoable_permissions = set(repoable_permissions_filtered)

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
        return errors

    if not commit:
        log_deleted_and_repoed_policies(
            deleted_policy_names, repoed_policies, role_name, account_number
        )
        return errors

    conn = config["connection_iam"]
    conn["account_number"] = account_number

    for name in deleted_policy_names:
        try:
            delete_policy(name, role, account_number, conn)
        except IAMError as e:
            LOGGER.error(e)
            errors.append(str(e))

    if repoed_policies:
        try:
            replace_policies(repoed_policies, role, account_number, conn)
        except IAMError as e:
            LOGGER.error(e)
            errors.append(str(e))

    current_policies = get_role_inline_policies(role.dict(), **conn) or {}
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
        update_repoed_description(role.role_name, conn)
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
    account_number: str,
    role_name: str,
    dynamo_table: Table,
    config: RepokidConfig,
    hooks: RepokidHooks,
    selection: int = 0,
    commit: bool = False,
) -> List[str]:
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
        role = get_role_data(dynamo_table, role_id)

    # no option selected, display a table of options
    if not selection:
        headers = ["Number", "Source", "Discovered", "Permissions", "Services"]
        rows = []
        for index, policies_version in enumerate(role.policies):
            policy_permissions, _ = roledata.get_permissions_in_policy(
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
        return errors

    conn = config["connection_iam"]
    conn["account_number"] = account_number

    current_policies = get_role_inline_policies(role.dict(), **conn)

    if selection:
        pp = pprint.PrettyPrinter()

        print("Will restore the following policies:")
        pp.pprint(role.policies[int(selection)]["Policy"])

        print("Current policies:")
        pp.pprint(current_policies)

        current_permissions, _ = roledata.get_permissions_in_policy(
            role.policies[-1]["Policy"]
        )
        selected_permissions, _ = roledata.get_permissions_in_policy(
            role.policies[int(selection)]["Policy"]
        )
        restored_permissions = set(selected_permissions) - set(current_permissions)

        print("\nResore will return these permissions:")
        print("\n".join([perm for perm in sorted(restored_permissions)]))

    if not commit:
        return errors

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
            message = (
                "Unable to push policy {}.  Error: {} (role: {} account {})".format(
                    policy_name, e.message, role.role_name, account_number
                )
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

            except botocore.exceptions.ClientError as e:
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
    account_number: str,
    dynamo_table: Table,
    config: RepokidConfig,
    hooks: RepokidHooks,
    commit: bool = False,
    scheduled: bool = True,
    limit: int = -1,
) -> None:
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
    roles = RoleList([])
    for role_id in role_ids_in_account:
        roles.append(
            get_role_data(
                dynamo_table,
                role_id,
                fields=["Active", "RoleName", "RepoScheduled"],
            )
        )

    roles = roles.get_active()

    if scheduled:
        roles = roles.get_scheduled()

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
    repoed = RoleList([])
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
        LOGGER.error(f"Error(s) during repo: {errors} (account: {account_number})")
    else:
        LOGGER.info(f"Successfully repoed {count} roles in account {account_number}")

    repokid.hooks.call_hooks(
        hooks,
        "AFTER_REPO_ROLES",
        {"account_number": account_number, "roles": repoed, "errors": errors},
    )


def _repo_stats(
    output_file: str, dynamo_table: Table, account_number: str = ""
) -> None:
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
        role = get_role_data(
            dynamo_table,
            roleID,
            fields=["RoleId", "RoleName", "Account", "Active", "Stats"],
        )
        for stats_entry in role.stats:
            rows.append(
                [
                    role.role_id,
                    role.role_name,
                    role.account,
                    role.active,
                    stats_entry["Date"],
                    stats_entry["Source"],
                    stats_entry["PermissionsCount"],
                    stats_entry.get("RepoablePermissionsCount", 0),
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
