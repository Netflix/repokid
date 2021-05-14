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
import copy
import logging
from typing import Any
from typing import Dict
from typing import List
from typing import Set
from typing import Tuple

import repokid.hooks
from repokid.role import Role
from repokid.role import RoleList
from repokid.types import RepokidHooks
from repokid.utils.dynamo import get_all_role_ids_for_account
from repokid.utils.permissions import _get_potentially_repoable_permissions

LOGGER = logging.getLogger("repokid")


def find_and_mark_inactive(account_number: str, active_roles: RoleList) -> None:
    """
    Mark roles in the account that aren't currently active inactive. Do this by getting all roles in the account and
    subtracting the active roles, any that are left are inactive and should be marked thusly.

    Args:
        account_number (string)
        active_roles (set): the currently active roles discovered in the most recent scan

    Returns:
        None
    """
    known_roles = set(get_all_role_ids_for_account(account_number))
    inactive_roles: Set[Role] = {
        role for role in active_roles if role.role_id not in known_roles
    }

    for role in inactive_roles:
        if role.active:
            role.mark_inactive()


def _convert_repoed_service_to_sorted_perms_and_services(
    repoed_services: Set[str],
) -> Tuple[List[str], List[str]]:
    """
    Repokid stores a field RepoableServices that historically only stored services (when Access Advisor was only data).
    Now this field is repurposed to store both services and permissions.  We can tell the difference because permissions
    always have the form <service>:<permission>.  This function splits the contents of the field to sorted sets of
    repoable services and permissions.

    Args:
        repoed_services (list): List from Dynamo of repoable services and permissions

    Returns:
        list: Sorted list of repoable permissions (where there are other permissions that aren't repoed)
        list: Sorted list of repoable services (where the entire service is removed)
    """
    repoable_permissions = set()
    repoable_services = set()

    for entry in repoed_services:
        if len(entry.split(":")) == 2:
            repoable_permissions.add(entry)
        else:
            repoable_services.add(entry)

    return sorted(repoable_permissions), sorted(repoable_services)


def _get_repoable_permissions_batch(
    repo_able_roles: RoleList,
    permissions_dict: Dict[str, Any],
    minimum_age: int,
    hooks: RepokidHooks,
    batch_size: int,
) -> Dict[str, Any]:
    """
    Generate a dictionary mapping of role arns to their repoable permissions based on the list of all permissions the
    role's policies currently allow and Access Advisor data for the services included in the role's policies.

    The first step is to come up with a list of services that were used within the time threshold (the same defined)
    in the age filter config. Permissions are repoable if they aren't in the used list, aren't in the constant list
    of unsupported services/actions (IAM_ACCESS_ADVISOR_UNSUPPORTED_SERVICES, IAM_ACCESS_ADVISOR_UNSUPPORTED_ACTIONS),
    and aren't being temporarily ignored because they're on the no_repo_permissions list (newly added).

    Args:
    repo_able_roles: (list): List of the roles that can be checked for repoing
    permissions_dict (dict): Mapping role arns to their full list of permissions that the role's permissions allow
    minimum_age: Minimum age of a role (in days) for it to be repoable
    hooks: Dict containing hook names and functions to run

    Returns:
        dict: Mapping role arns to set of permissions that are 'repoable' (not used within the time threshold)
    """

    if len(repo_able_roles) == 0:
        return {}

    repo_able_roles_batches = copy.deepcopy(repo_able_roles)
    potentially_repoable_permissions_dict = {}
    repoable_dict = {}
    repoable_log_dict = {}

    for role in repo_able_roles:
        potentially_repoable_permissions_dict[
            role.arn
        ] = _get_potentially_repoable_permissions(
            role.role_name,
            role.account,
            role.aa_data or [],
            permissions_dict[role.arn],
            role.no_repo_permissions,
            minimum_age,
        )

    while len(repo_able_roles_batches) > 0:
        role_batch = repo_able_roles_batches[:batch_size]
        repo_able_roles_batches = repo_able_roles_batches[batch_size:]

        hooks_output = repokid.hooks.call_hooks(
            hooks,
            "DURING_REPOABLE_CALCULATION_BATCH",
            {
                "role_batch": role_batch,
                "potentially_repoable_permissions": potentially_repoable_permissions_dict,
                "minimum_age": minimum_age,
            },
        )
        for role_arn, output in list(hooks_output.items()):
            repoable = {
                permission_name
                for permission_name, permission_value in list(
                    output["potentially_repoable_permissions"].items()
                )
                if permission_value.repoable
            }
            repoable_dict[role_arn] = repoable
            repoable_log_dict[role_arn] = "".join(
                "{}: {}\n".format(perm, decision.decider)
                for perm, decision in list(
                    output["potentially_repoable_permissions"].items()
                )
            )

    for role in repo_able_roles:
        LOGGER.debug(
            "Repoable permissions for role {role_name} in {account_number}:\n{repoable}".format(
                role_name=role.role_name,
                account_number=role.account,
                repoable=repoable_log_dict[role.arn],
            )
        )
    return repoable_dict
