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
import json
import logging
import pprint
from typing import Iterable
from typing import List

import botocore
from cloudaux.aws.iam import delete_role_policy
from cloudaux.aws.iam import get_role_inline_policies
from cloudaux.aws.iam import put_role_policy
from tabulate import tabulate

import repokid.hooks
from repokid.datasource.access_advisor import AccessAdvisorDatasource
from repokid.datasource.iam import IAMDatasource
from repokid.role import Role
from repokid.role import RoleList
from repokid.types import RepokidConfig
from repokid.types import RepokidHooks
from repokid.utils.dynamo import find_role_in_cache
from repokid.utils.dynamo import role_ids_for_all_accounts
from repokid.utils.permissions import get_services_in_permissions

LOGGER = logging.getLogger("repokid")


def _repo_role(
    account_number: str,
    role_name: str,
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
    role_id = find_role_in_cache(role_name, account_number)
    # only load partial data that we need to determine if we should keep going
    role = Role(role_id=role_id, config=config)
    role.fetch()
    return role.repo(hooks, commit=commit, scheduled=scheduled)


def _rollback_role(
    account_number: str,
    role_name: str,
    config: RepokidConfig,
    hooks: RepokidHooks,
    selection: int = -1,
    commit: bool = False,
) -> List[str]:
    """
    Display the historical policy versions for a role as a numbered list.  Restore to a specific version if selected.
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

    role_id = find_role_in_cache(role_name, account_number)
    if not role_id:
        message = "Could not find role with name {} in account {}".format(
            role_name, account_number
        )
        errors.append(message)
        LOGGER.warning(message)
        return errors
    else:
        role = Role(role_id=role_id)
        role.fetch()

    # no option selected, display a table of options
    if selection < 0:
        headers = ["Number", "Source", "Discovered", "Permissions", "Services"]
        rows = []
        for index, policies_version in enumerate(role.policies):
            policy_permissions, _ = repokid.utils.permissions.get_permissions_in_policy(
                policies_version["Policy"]
            )
            rows.append(
                [
                    index,
                    policies_version["Source"],
                    policies_version["Discovered"],
                    len(policy_permissions),
                    get_services_in_permissions(policy_permissions),
                ]
            )
        print(tabulate(rows, headers=headers))
        return errors

    conn = config["connection_iam"]
    conn["account_number"] = account_number

    current_policies = get_role_inline_policies(role.dict(by_alias=True), **conn)

    pp = pprint.PrettyPrinter()

    print("Will restore the following policies:")
    pp.pprint(role.policies[int(selection)]["Policy"])

    print("Current policies:")
    pp.pprint(current_policies)

    current_permissions, _ = role.get_permissions_for_policy_version()
    selected_permissions, _ = role.get_permissions_for_policy_version(
        selection=selection
    )
    restored_permissions = selected_permissions - current_permissions

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

    role.store()
    role.gather_role_data(
        hooks, current_policies=current_policies, source="Restore", add_no_repo=False
    )

    if not errors:
        LOGGER.info(
            f"Successfully restored selected version {selection} of role policies (role: {role.role_name} "
            f"account: {account_number}"
        )
    return errors


def _repo_all_roles(
    account_number: str,
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
    access_advisor_datasource = AccessAdvisorDatasource()
    access_advisor_datasource.seed(account_number)
    iam_datasource = IAMDatasource()
    role_ids = iam_datasource.seed(account_number)
    errors = []

    roles = RoleList.from_ids(role_ids, config=config)
    roles = roles.get_active()
    if scheduled:
        roles = roles.get_scheduled()
    if not roles:
        LOGGER.info(f"No roles to repo in account {account_number}")
        return

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
        role_errors = role.repo(hooks, commit=commit, scheduled=scheduled)
        if role_errors:
            errors.extend(role_errors)
        repoed.append(role)
        count += 1

    if errors:
        LOGGER.error(f"Error(s) during repo in account: {account_number}: {errors}")
    LOGGER.info(f"Successfully repoed {count} roles in account {account_number}")

    repokid.hooks.call_hooks(
        hooks,
        "AFTER_REPO_ROLES",
        {"account_number": account_number, "roles": repoed, "errors": errors},
    )


def _repo_stats(output_file: str, account_number: str = "") -> None:
    """
    Create a csv file with stats about roles, total permissions, and applicable filters over time

    Args:
        output_file (string): the name of the csv file to write
        account_number (string): if specified only display roles from selected account, otherwise display all

    Returns:
        None
    """
    role_ids: Iterable[str]
    if account_number:
        access_advisor_datasource = AccessAdvisorDatasource()
        access_advisor_datasource.seed(account_number)
        iam_datasource = IAMDatasource()
        role_ids = iam_datasource.seed(account_number)
    else:
        role_ids = role_ids_for_all_accounts()

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
    roles = RoleList.from_ids(
        role_ids, fields=["RoleId", "RoleName", "Account", "Active", "Stats"]
    )

    for role in roles:
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
