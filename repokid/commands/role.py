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
from typing import Any
from typing import List
from typing import Optional

import tabview as t
from policyuniverse.arn import ARN
from tabulate import tabulate
from tqdm import tqdm

import repokid.hooks
from repokid.exceptions import MissingRepoableServices
from repokid.role import Role
from repokid.role import RoleList
from repokid.types import RepokidConfig
from repokid.types import RepokidHooks
from repokid.utils.dynamo import find_role_in_cache
from repokid.utils.dynamo import get_all_role_ids_for_account
from repokid.utils.dynamo import role_arns_for_all_accounts
from repokid.utils.iam import inline_policies_size_exceeds_maximum
from repokid.utils.permissions import get_permissions_in_policy
from repokid.utils.permissions import get_services_in_permissions

LOGGER = logging.getLogger("repokid")


def _display_roles(account_number: str, inactive: bool = False) -> None:
    """
    Display a table with data about all roles in an account and write a csv file with the data.

    Args:
        account_number (string)
        inactive (bool): show roles that have historically (but not currently) existed in the account if True

    Returns:
        None
    """
    headers = [
        "Name",
        "Refreshed",
        "Disqualified By",
        "Can be repoed",
        "Permissions",
        "Repoable",
        "Repoed",
        "Services",
    ]

    rows: List[List[Any]] = []

    role_ids = get_all_role_ids_for_account(account_number)
    roles = RoleList.from_ids(role_ids)

    if not inactive:
        roles = roles.get_active()

    for role in roles:
        rows.append(
            [
                role.role_name,
                role.refreshed,
                role.disqualified_by,
                len(role.disqualified_by) == 0,
                role.total_permissions,
                role.repoable_permissions,
                role.repoed,
                role.repoable_services,
            ]
        )

    rows = sorted(rows, key=lambda x: (x[5], x[0], x[4]))
    rows.insert(0, headers)
    # print tabulate(rows, headers=headers)
    t.view(rows)
    with open("table.csv", "w") as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(headers)
        for row in rows:
            csv_writer.writerow(row)


def _find_roles_with_permissions(permissions: List[str], output_file: str) -> None:
    """
    Search roles in all accounts for a policy with any of the provided permissions, log the ARN of each role.

    Args:
        permissions (list[string]): The name of the permissions to find
        output_file (string): filename to write the output

    Returns:
        None
    """
    arns: List[str] = list()
    role_ids = role_arns_for_all_accounts()
    roles = RoleList.from_ids(
        role_ids, fields=["Policies", "RoleName", "Arn", "Active"]
    )
    for role in roles:
        role_permissions, _ = role.get_permissions_for_policy_version()

        permissions_set = set([p.lower() for p in permissions])
        found_permissions = permissions_set.intersection(role_permissions)

        if found_permissions and role.active:
            arns.append(role.arn)
            LOGGER.info(
                "ARN {arn} has {permissions}".format(
                    arn=role.arn, permissions=list(found_permissions)
                )
            )

    if not output_file:
        return

    with open(output_file, "w") as fd:
        json.dump(arns, fd)

    LOGGER.info(f"Output written to file {output_file}")


def _display_role(
    account_number: str,
    role_name: str,
    config: RepokidConfig,
) -> None:
    """
    Displays data about a role in a given account:
      1) Name, which filters are disqualifying it from repo, if it's repoable, total/repoable permissions,
         when it was last repoed, which services can be repoed
      2) The policy history: how discovered (repo, scan, etc), the length of the policy, and start of the contents
      3) Captured stats entry for the role
      4) A list of all services/actions currently allowed and whether they are repoable
      5) What the new policy would look like after repoing (if it is repoable)

    Args:
        account_number (string)
        role_name (string)

    Returns:
        None
    """
    role_id = find_role_in_cache(role_name, account_number)
    if not role_id:
        LOGGER.warning("Could not find role with name {}".format(role_name))
        return

    role = Role(role_id=role_id)
    role.fetch()

    print("\n\nRole repo data:")
    headers = [
        "Name",
        "Refreshed",
        "Disqualified By",
        "Can be repoed",
        "Permissions",
        "Repoable",
        "Repoed",
        "Services",
    ]
    rows = [
        [
            role.role_name,
            role.refreshed,
            role.disqualified_by,
            len(role.disqualified_by) == 0,
            role.total_permissions,
            role.repoable_permissions,
            role.repoed,
            role.repoable_services,
        ]
    ]
    print(tabulate(rows, headers=headers) + "\n\n")

    print("Policy history:")
    headers = ["Number", "Source", "Discovered", "Permissions", "Services"]
    rows = []
    for index, policies_version in enumerate(role.policies):
        policy_permissions, _ = get_permissions_in_policy(policies_version["Policy"])
        rows.append(
            [
                index,
                policies_version["Source"],
                policies_version["Discovered"],
                len(policy_permissions),
                get_services_in_permissions(policy_permissions),
            ]
        )
    print(tabulate(rows, headers=headers) + "\n\n")

    print("Stats:")
    headers = ["Date", "Event Type", "Permissions Count", "Disqualified By"]
    rows = []
    for stats_entry in role.stats:
        rows.append(
            [
                stats_entry["Date"],
                stats_entry["Source"],
                stats_entry["PermissionsCount"],
                stats_entry.get("DisqualifiedBy", []),
            ]
        )
    print(tabulate(rows, headers=headers) + "\n\n")

    # can't do anymore if we don't have AA data
    if not role.aa_data:
        LOGGER.warning("ARN not found in Access Advisor: {}".format(role.arn))
        return

    warn_unknown_permissions = config.get("warnings", {}).get(
        "unknown_permissions", False
    )

    permissions, eligible_permissions = role.get_permissions_for_policy_version(
        warn_unknown_perms=warn_unknown_permissions
    )

    print("Repoable services and permissions")
    headers = ["Service", "Action", "Repoable"]
    rows = []
    for permission in permissions:
        service = permission.split(":")[0]
        action = permission.split(":")[1]
        is_repoable_permission = permission in role.repoable_services
        is_repoable_service = permission.split(":")[0] in role.repoable_services
        # repoable is is True if the action (`permission`) is in the list of repoable
        # services OR if the service (`permission.split(":")[0]`) is in the list
        repoable = is_repoable_permission or is_repoable_service
        rows.append([service, action, repoable])

    rows = sorted(rows, key=lambda x: (x[2], x[0], x[1]))
    print(tabulate(rows, headers=headers) + "\n\n")

    try:
        repoed_policies, _ = role.get_repoed_policy()
        print(
            "Repo'd Policies: \n{}".format(
                json.dumps(repoed_policies, indent=2, sort_keys=True)
            )
        )
    except MissingRepoableServices:
        print("All Policies Removed")
        repoed_policies = {}

    # need to check if all policies would be too large
    if inline_policies_size_exceeds_maximum(repoed_policies):
        LOGGER.warning(
            "Policies would exceed the AWS size limit after repo for role: {}.  "
            "Please manually minify.".format(role_name)
        )


def _remove_permissions_from_roles(
    permissions: List[str],
    role_filename: str,
    config: Optional[RepokidConfig],
    hooks: RepokidHooks,
    commit: bool = False,
) -> None:
    """Loads roles specified in file and calls _remove_permissions_from_role() for each one.

    Args:
        permissions (list<string>)
        role_filename (string)
        commit (bool)

    Returns:
        None
    """
    with open(role_filename, "r") as fd:
        roles = json.load(fd)

    for role_arn in tqdm(roles):
        arn = ARN(role_arn)
        if arn.error:
            LOGGER.error("INVALID ARN: {arn}".format(arn=role_arn))
            return

        account_number = arn.account_number
        role_name = arn.name.split("/")[-1]

        role_id = find_role_in_cache(role_name, account_number)
        role = Role(role_id=role_id, config=config)
        role.fetch()

        role.remove_permissions(permissions, hooks, commit=commit)

        repokid.hooks.call_hooks(hooks, "AFTER_REPO", {"role": role})
