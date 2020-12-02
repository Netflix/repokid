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
import datetime
import logging
import time
from collections import defaultdict
from typing import Any
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple

from cloudaux.aws.iam import get_role_inline_policies
from dateutil.tz import tzlocal
from mypy_boto3_dynamodb.service_resource import Table
from policyuniverse import all_permissions
from policyuniverse import expand_policy
from policyuniverse import get_actions_from_statement

import repokid.hooks
from repokid import CONFIG as CONFIG
from repokid.exceptions import RoleNotFoundError
from repokid.role import Role
from repokid.role import RoleList
from repokid.types import RepokidConfig
from repokid.types import RepokidHooks
from repokid.utils.aardvark import get_aardvark_data
from repokid.utils.dynamo import add_to_end_of_list
from repokid.utils.dynamo import get_role_data
from repokid.utils.dynamo import role_ids_for_account
from repokid.utils.dynamo import set_role_data
from repokid.utils.dynamo import store_initial_role_data

LOGGER = logging.getLogger("repokid")
BEGINNING_OF_2015_MILLI_EPOCH = 1420113600000
IAM_ACCESS_ADVISOR_UNSUPPORTED_SERVICES = frozenset([""])
IAM_ACCESS_ADVISOR_UNSUPPORTED_ACTIONS = frozenset(["iam:passrole"])

STATEMENT_SKIP_SID = "NOREPO"


# permission decisions have the form repoable - boolean, and decider - string
class RepoablePermissionDecision(object):
    def __init__(self) -> None:
        self.repoable: Optional[bool] = None
        self.decider: str = ""

    def __repr__(self) -> str:
        return "Is repoable: {}, Decider: {}".format(self.repoable, self.decider)


def add_new_policy_version(
    dynamo_table: Table, role: Role, current_policy: Dict[str, Any], update_source: str
) -> None:
    """
    Create a new entry in the history of policy versions in Dynamo. The entry contains the source of the new policy:
    (scan, repo, or restore) the current time, and the current policy contents. Updates the role's policies with the
    full policies including the latest.

    Args:
        dynamo_table
        role (Role)
        current_policy (dict)
        update_source (string): ['Repo', 'Scan', 'Restore']

    Returns:
        None
    """
    policy_entry = {
        "Source": update_source,
        "Discovered": datetime.datetime.utcnow().isoformat(),
        "Policy": current_policy,
    }

    add_to_end_of_list(dynamo_table, role.role_id, "Policies", policy_entry)
    temp_role = get_role_data(dynamo_table, role.role_id, fields=["Policies"])
    role.policies = temp_role.policies
    # TODO(psanders): return new role instead of mutating


def find_and_mark_inactive(
    dynamo_table: Table, account_number: str, active_roles: RoleList
) -> None:
    """
    Mark roles in the account that aren't currently active inactive. Do this by getting all roles in the account and
    subtracting the active roles, any that are left are inactive and should be marked thusly.

    Args:
        dynamo_table
        account_number (string)
        active_roles (set): the currently active roles discovered in the most recent scan

    Returns:
        None
    """

    active_roles_set = set(active_roles)
    known_roles = set(role_ids_for_account(dynamo_table, account_number))
    inactive_roles = known_roles - active_roles_set

    for roleID in inactive_roles:
        role = get_role_data(dynamo_table, roleID, fields=["Active", "Arn"])
        if role.active:
            set_role_data(dynamo_table, roleID, {"Active": False})


def find_newly_added_permissions(
    old_policy: Dict[str, Any], new_policy: Dict[str, Any]
) -> Set[str]:
    """
    Compare and old version of policies to a new version and return a set of permissions that were added.  This will
    be used to maintain a list of permissions that were newly added and should not be repoed for a period of time.

    Args:
        old_policy
        new_policy

    Returns:
        set: Exapnded set of permissions that are in the new policy and not the old one
    """
    old_permissions, _ = get_permissions_in_policy(old_policy)
    new_permissions, _ = get_permissions_in_policy(new_policy)
    return set(new_permissions) - set(old_permissions)


def update_no_repo_permissions(
    dynamo_table: Table, role: Role, newly_added_permissions: Set[str]
) -> None:
    """
    Update Dyanmo entry for newly added permissions. Any that were newly detected get added with an expiration
    date of now plus the config setting for 'repo_requirements': 'exclude_new_permissions_for_days'. Expired entries
    get deleted. Also update the role object with the new no-repo-permissions.

    Args:
        dynamo_table
        role
        newly_added_permissions (set)

    Returns:
        None
    """
    current_ignored_permissions = role.no_repo_permissions
    new_ignored_permissions = {}

    current_time = int(time.time())
    new_perms_expire_time = current_time + (
        24
        * 60
        * 60
        * CONFIG["repo_requirements"].get("exclude_new_permissions_for_days", 14)
    )

    # only copy non-expired items to the new dictionary
    for permission, expire_time in list(current_ignored_permissions.items()):
        if expire_time > current_time:
            new_ignored_permissions[permission] = current_ignored_permissions[
                permission
            ]

    for permission in newly_added_permissions:
        new_ignored_permissions[permission] = new_perms_expire_time

    role.no_repo_permissions = new_ignored_permissions
    set_role_data(
        dynamo_table, role.role_id, {"NoRepoPermissions": role.no_repo_permissions}
    )
    # TODO(psanders): return new role instead of mutating


def update_opt_out(dynamo_table: Table, role: Role) -> None:
    """
    Update opt-out object for a role - remove (set to empty dict) any entries that have expired
    Opt-out objects should have the form {'expire': xxx, 'owner': xxx, 'reason': xxx}

    Args:
        dynamo_table
        role

    Returns:
        None
    """
    if role.opt_out and int(role.opt_out["expire"]) < int(time.time()):
        set_role_data(dynamo_table, role.role_id, {"OptOut": {}})


def update_role_data(
    dynamo_table: Table,
    account_number: str,
    role: Role,
    current_policy: Dict[str, Any],
    source: str = "Scan",
    add_no_repo: bool = True,
) -> Role:
    """
    Compare the current version of a policy for a role and what has been previously stored in Dynamo.
      - If current and new policy versions are different store the new version in Dynamo. Add any newly added
          permissions to temporary permission blocklist. Purge any old entries from permission blocklist.
      - Refresh the updated time on the role policy
      - If the role is completely new, store the first version in Dynamo
      - Updates the role with full history of policies, including current version

    Args:
        dynamo_table
        account_number
        role (Role): current role being updated
        current_policy (dict): representation of the current policy version
        source: Default 'Scan' but could be Repo, Rollback, etc
        add_no_repo (bool)

    Returns:
        role
    """

    # policy_entry: source, discovered, policy
    try:
        stored_role = get_role_data(
            dynamo_table, role.role_id, fields=["OptOut", "Policies", "Tags"]
        )
    except RoleNotFoundError:
        stored_role = None

    if not stored_role:
        role_dict = store_initial_role_data(
            dynamo_table,
            role.arn,
            role.create_date,
            role.role_id,
            role.role_name,
            account_number,
            current_policy,
            role.tags,
        )
        role_updates = Role.parse_obj(role_dict)
        update_dict = role_updates.dict(exclude_unset=True)
        role = role.copy(update=update_dict)
        LOGGER.info("Added new role ({}): {}".format(role.role_id, role.arn))
        return role
    else:
        # is the policy list the same as the last we had?
        old_policy = stored_role.policies[-1]["Policy"]
        if current_policy != old_policy:
            add_new_policy_version(dynamo_table, role, current_policy, source)
            LOGGER.info(
                "{} has different inline policies than last time, adding to role store".format(
                    role.arn
                )
            )

            newly_added_permissions = find_newly_added_permissions(
                old_policy, current_policy
            )
        else:
            newly_added_permissions = set()

        # update tags if needed
        if role.tags != stored_role.tags:
            set_role_data(dynamo_table, role.role_id, {"Tags": role.tags})

        if add_no_repo:
            update_no_repo_permissions(dynamo_table, role, newly_added_permissions)
        update_opt_out(dynamo_table, role)
        set_role_data(
            dynamo_table,
            role.role_id,
            {"Refreshed": datetime.datetime.utcnow().isoformat()},
        )

        # Update all data from Dynamo except CreateDate (it's in the wrong format) and DQ_by (we're going to recalc)
        current_role = get_role_data(dynamo_table, role.role_id)
        current_role.create_date = None
        current_role.disqualified_by = []

        # Create an updated Role model to be returned to the caller
        update_dict = current_role.dict(exclude_unset=True)
        role = role.copy(update=update_dict)

        return role


def update_stats(dynamo_table: Table, roles: RoleList, source: str = "Scan") -> None:
    """
    Create a new stats entry for each role in a set of roles and add it to Dynamo

    Args:
        dynamo_table
        roles (Roles): a list of all the role objects to update data for
        source (string): the source of the new stats data (repo, scan, etc)

    Returns:
        None
    """
    for role in roles:
        new_stats = {
            "Date": datetime.datetime.utcnow().isoformat(),
            "DisqualifiedBy": role.disqualified_by,
            "PermissionsCount": role.total_permissions,
            "RepoablePermissionsCount": role.repoable_permissions,
            "Source": source,
        }
        try:
            cur_stats = role.stats[-1]
        except IndexError:
            cur_stats = {
                "DisqualifiedBy": [],
                "PermissionsCount": 0,
                "RepoablePermissionsCount": 0,
            }

        for item in ["DisqualifiedBy", "PermissionsCount", "RepoablePermissionsCount"]:
            if new_stats.get(item) != cur_stats.get(item):
                add_to_end_of_list(dynamo_table, role.role_id, "Stats", new_stats)


def _update_repoable_services(
    role: Role, repoable_permissions: Set[str], eligible_permissions: Set[str]
) -> None:
    (
        repoable_permissions_set,
        repoable_services_set,
    ) = _convert_repoable_perms_to_perms_and_services(
        eligible_permissions, repoable_permissions
    )

    # we're going to store both repoable permissions and repoable services in the field "RepoableServices"
    role.repoable_services = list(repoable_services_set.union(repoable_permissions_set))
    role.repoable_permissions = len(repoable_permissions)
    # TODO(psanders): return new role instead of mutating


def _calculate_repo_scores(
    roles: RoleList,
    minimum_age: int,
    hooks: RepokidHooks,
    batch: bool = False,
    batch_size: int = 100,
) -> None:
    """
    Get the total and repoable permissions count and set of repoable services for every role in the account.
    For each role:
      1) call _get_role_permissions
      2) call _get_repoable_permissions (count), repoable_permissions (count), and repoable_services (list) for role

    Each time we got the role permissions we built a list of any permissions that the role's policies granted access
    to but weren't in our master list of permissions AWS has.  At the end of this run we'll warn about any of these.

    Args:
        roles (Roles): The set of all roles we're analyzing
        minimum_age
        hooks

    Returns:
        None
    """
    repo_able_roles = RoleList([])
    eligible_permissions_dict = {}
    for role in roles:
        total_permissions, eligible_permissions = _get_role_permissions(role)
        role.total_permissions = len(total_permissions)

        # if we don't have any access advisor data for a service than nothing is repoable
        if not role.aa_data:
            LOGGER.info("No data found in access advisor for {}".format(role.role_id))
            role.repoable_permissions = 0
            role.repoable_services = []
            continue

        # permissions are only repoable if the role isn't being disqualified by filter(s)
        if len(role.disqualified_by) == 0:
            repo_able_roles.append(role)
            eligible_permissions_dict[role.arn] = eligible_permissions
        else:
            role.repoable_permissions = 0
            role.repoable_services = []

    repoable_permissions_dict = {}
    if batch:
        repoable_permissions_dict = _get_repoable_permissions_batch(
            repo_able_roles, eligible_permissions_dict, minimum_age, hooks, batch_size
        )
    else:
        for role in repo_able_roles:
            repoable_permissions_dict[role.arn] = _get_repoable_permissions(
                role.account,
                role.role_name,
                eligible_permissions_dict[role.arn],
                role.aa_data or [],
                role.no_repo_permissions,
                role.role_id,
                minimum_age,
                hooks,
            )

    for role in repo_able_roles:
        eligible_permissions = eligible_permissions_dict[role.arn]
        repoable_permissions = repoable_permissions_dict[role.arn]
        _update_repoable_services(role, repoable_permissions, eligible_permissions)


def _convert_repoable_perms_to_perms_and_services(
    total_permissions: Set[str], repoable_permissions: Set[str]
) -> Tuple[Set[str], Set[str]]:
    """
    Take a list of total permissions and repoable permissions and determine whether only a few permissions are being
    repoed or if the entire service (all permissions from that service) are being removed.

    Args:
        total_permissions (set): A list of the total permissions a role has
        repoable_permissions (set): A list of repoable permissions suggested to be removed

    Returns:
        set: Set of permissions that will be individually removed but other permissions from the service will
              be kept
        set: Set of services that will be completely removed
    """
    repoed_permissions: Set[str] = set()
    repoed_services: Set[str] = set()

    total_perms_by_service = defaultdict(list)
    repoable_perms_by_service = defaultdict(list)

    # group total permissions and repoable permissions by service
    for perm in total_permissions:
        total_perms_by_service[perm.split(":")[0]].append(perm)

    for perm in repoable_permissions:
        repoable_perms_by_service[perm.split(":")[0]].append(perm)

    for service in repoable_perms_by_service:
        if all(
            perm in repoable_perms_by_service[service]
            for perm in total_perms_by_service[service]
        ):
            repoed_services.add(service)
        else:
            repoed_permissions.update(
                perm for perm in repoable_perms_by_service[service]
            )

    return repoed_permissions, repoed_services


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


def _filter_scheduled_repoable_perms(
    repoable_permissions: Set[str], scheduled_perms: Set[str]
) -> List[str]:
    """
    Take a list of current repoable permissions and filter out any that weren't in the list of scheduled permissions

    Args:
        repoable_permissions (list): List of expanded permissions that are currently believed repoable
        scheduled_perms (list): List of scheduled permissions and services (stored in Dynamo at schedule time)
    Returns:
        list: New (filtered) repoable permissions
    """
    (
        scheduled_permissions,
        scheduled_services,
    ) = _convert_repoed_service_to_sorted_perms_and_services(scheduled_perms)
    filtered = [
        perm
        for perm in repoable_permissions
        if (perm in scheduled_permissions or perm.split(":")[0] in scheduled_services)
    ]
    return sorted(filtered)


def _get_epoch_authenticated(service_authenticated: int) -> Tuple[int, bool]:
    """
    Ensure service authenticated from Access Advisor is in seconds epoch

    Args:
        service_authenticated (int): The service authenticated time from Access Advisor

    Returns:
        int: The epoch time in seconds that the service was last authenticated
        bool: Whether the service authenticated was valid
    """
    current_time = int(time.time())
    if service_authenticated == 0:
        return 0, True

    # we have an odd timestamp, try to check
    elif BEGINNING_OF_2015_MILLI_EPOCH < service_authenticated < (current_time * 1000):
        return int(service_authenticated / 1000), True

    elif (BEGINNING_OF_2015_MILLI_EPOCH / 1000) < service_authenticated < current_time:
        return service_authenticated, True

    else:
        return -1, False


def _get_potentially_repoable_permissions(
    role_name: str,
    account_number: str,
    aa_data: List[Dict[str, Any]],
    permissions: Set[str],
    no_repo_permissions: Dict[str, int],
    minimum_age: int,
) -> Dict[str, Any]:
    ago = datetime.timedelta(minimum_age)
    now = datetime.datetime.now(tzlocal())

    current_time = time.time()
    no_repo_list = [
        perm.lower()
        for perm in no_repo_permissions
        if no_repo_permissions[perm] > current_time
    ]

    # cast all permissions to lowercase
    permissions = {permission.lower() for permission in permissions}
    potentially_repoable_permissions = {
        permission: RepoablePermissionDecision()
        for permission in permissions
        if permission not in no_repo_list
    }

    used_services = set()
    for service in aa_data:
        (accessed, valid_authenticated) = _get_epoch_authenticated(
            service["lastAuthenticated"]
        )

        if not accessed:
            continue

        if not valid_authenticated:
            LOGGER.error(
                "Got malformed Access Advisor data for {role_name} in {account_number} for service {service}"
                ": {last_authenticated}".format(
                    role_name=role_name,
                    account_number=account_number,
                    service=service.get("serviceNamespace"),
                    last_authenticated=service["lastAuthenticated"],
                )
            )
            used_services.add(service["serviceNamespace"])

        accessed_dt = datetime.datetime.fromtimestamp(accessed, tzlocal())
        if accessed_dt > now - ago:
            used_services.add(service["serviceNamespace"])

    for (
        permission_name,
        permission_decision,
    ) in potentially_repoable_permissions.items():
        if permission_name.split(":")[0] in IAM_ACCESS_ADVISOR_UNSUPPORTED_SERVICES:
            LOGGER.info("skipping {}".format(permission_name))
            continue

        # we have an unused service but need to make sure it's repoable
        if permission_name.split(":")[0] not in used_services:
            if permission_name in IAM_ACCESS_ADVISOR_UNSUPPORTED_ACTIONS:
                LOGGER.info("skipping {}".format(permission_name))
                continue

            permission_decision.repoable = True
            permission_decision.decider = "Access Advisor"

    return potentially_repoable_permissions


def _get_repoable_permissions(
    account_number: str,
    role_name: str,
    permissions: Set[str],
    aa_data: List[Dict[str, Any]],
    no_repo_permissions: Dict[str, Any],
    role_id: str,
    minimum_age: int,
    hooks: RepokidHooks,
) -> Set[str]:
    """
    Generate a list of repoable permissions for a role based on the list of all permissions the role's policies
    currently allow and Access Advisor data for the services included in the role's policies.

    The first step is to come up with a list of services that were used within the time threshold (the same defined)
    in the age filter config. Permissions are repoable if they aren't in the used list, aren't in the constant list
    of unsupported services/actions (IAM_ACCESS_ADVISOR_UNSUPPORTED_SERVICES, IAM_ACCESS_ADVISOR_UNSUPPORTED_ACTIONS),
    and aren't being temporarily ignored because they're on the no_repo_permissions list (newly added).

    Args:
        account_number
        role_name
        permissions (set): The full set of permissions that the role's permissions allow
        aa_data (list): A list of Access Advisor data for a role. Each element is a dictionary with a couple required
                        attributes: lastAuthenticated (epoch time in milliseconds when the service was last used and
                        serviceNamespace (the service used)
        no_repo_permissions (dict): Keys are the name of permissions and values are the time the entry expires
        minimum_age: Minimum age of a role (in days) for it to be repoable
        hooks: Dict containing hook names and functions to run

    Returns:
        set: Permissions that are 'repoable' (not used within the time threshold)
    """
    potentially_repoable_permissions = _get_potentially_repoable_permissions(
        role_name,
        account_number,
        aa_data,
        permissions,
        no_repo_permissions,
        minimum_age,
    )

    hooks_output = repokid.hooks.call_hooks(
        hooks,
        "DURING_REPOABLE_CALCULATION",
        {
            "account_number": account_number,
            "role_name": role_name,
            "potentially_repoable_permissions": potentially_repoable_permissions,
            "minimum_age": minimum_age,
            "role_id": role_id,
        },
    )

    LOGGER.debug(
        "Repoable permissions for role {role_name} in {account_number}:\n{repoable}".format(
            role_name=role_name,
            account_number=account_number,
            repoable="".join(
                "{}: {}\n".format(perm, decision.decider)
                for perm, decision in list(
                    hooks_output["potentially_repoable_permissions"].items()
                )
            ),
        )
    )

    return {
        permission_name
        for permission_name, permission_value in list(
            hooks_output["potentially_repoable_permissions"].items()
        )
        if permission_value.repoable
    }


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


def _get_repoed_policy(
    policies: Dict[str, Any], repoable_permissions: Set[str]
) -> Tuple[Dict[str, Any], List[str]]:
    """
    This function contains the logic to rewrite the policy to remove any repoable permissions. To do so we:
      - Iterate over role policies
      - Iterate over policy statements
      - Skip Deny statements
      - Remove any actions that are in repoable_permissions
      - Remove any statements that now have zero actions
      - Remove any policies that now have zero statements

    Args:
        policies (dict): All of the inline policies as a dict with name and policy contents
        repoable_permissions (set): A set of all of the repoable permissions for policies

    Returns:
        dict: The rewritten set of all inline policies
        list: Any policies that are now empty as a result of the rewrites
    """
    # work with our own copy; don't mess with the CACHE copy.
    role_policies = copy.deepcopy(policies)

    empty_policies = []
    for policy_name, policy in list(role_policies.items()):
        # list of indexes in the policy that are empty
        empty_statements = []

        if type(policy["Statement"]) is dict:
            policy["Statement"] = [policy["Statement"]]

        for idx, statement in enumerate(policy["Statement"]):
            if statement["Effect"].lower() == "allow":
                if "Sid" in statement and statement["Sid"].startswith(
                    STATEMENT_SKIP_SID
                ):
                    continue

                statement_actions = get_actions_from_statement(statement)

                if not statement_actions.intersection(repoable_permissions):
                    # No permissions are being taken away; let's not modify this statement at all.
                    continue

                statement_actions = statement_actions.difference(repoable_permissions)

                # get_actions_from_statement has already inverted this so our new statement should be 'Action'
                if "NotAction" in statement:
                    del statement["NotAction"]

                # by putting this into a set, we lose order, which may be confusing to someone.
                statement["Action"] = sorted(list(statement_actions))

                # mark empty statements to be removed
                if len(statement["Action"]) == 0:
                    empty_statements.append(idx)

        # do the actual removal of empty statements
        for idx in sorted(empty_statements, reverse=True):
            del policy["Statement"][idx]

        # mark empty policies to be removed
        if len(policy["Statement"]) == 0:
            empty_policies.append(policy_name)

    # do the actual removal of empty policies.
    for policy_name in empty_policies:
        del role_policies[policy_name]

    return role_policies, empty_policies


def get_permissions_in_policy(
    policy_dict: Dict[str, Any], warn_unknown_perms: bool = False
) -> Tuple[Set[str], Set[str]]:
    """
    Given a set of policies for a role, return a set of all allowed permissions

    Args:
        policy_dict
        warn_unknown_perms

    Returns
        tuple
        set - all permissions allowed by the policies
        set - all permisisons allowed by the policies not marked with STATEMENT_SKIP_SID
    """
    total_permissions: Set[str] = set()
    eligible_permissions: Set[str] = set()

    for policy_name, policy in list(policy_dict.items()):
        policy = expand_policy(policy=policy, expand_deny=False)
        for statement in policy.get("Statement"):
            if statement["Effect"].lower() == "allow":
                total_permissions = total_permissions.union(
                    get_actions_from_statement(statement)
                )
                if not (
                    "Sid" in statement
                    and statement["Sid"].startswith(STATEMENT_SKIP_SID)
                ):
                    # No Sid
                    # Sid exists, but doesn't start with STATEMENT_SKIP_SID
                    eligible_permissions = eligible_permissions.union(
                        get_actions_from_statement(statement)
                    )

    weird_permissions = total_permissions.difference(all_permissions)
    if weird_permissions and warn_unknown_perms:
        LOGGER.warning("Unknown permissions found: {}".format(weird_permissions))

    return total_permissions, eligible_permissions


def _get_role_permissions(
    role: Role, warn_unknown_perms: bool = False
) -> Tuple[Set[str], Set[str]]:
    """
    Expand the most recent version of policies from a role to produce a list of all the permissions that are allowed
    (permission is included in one or more statements that is allowed).  To perform expansion the policyuniverse
    library is used. The result is a list of all of the individual permissions that are allowed in any of the
    statements. If our resultant list contains any permissions that aren't listed in the master list of permissions
    we'll raise an exception with the set of unknown permissions found.

    Args:
        role (Role): The role object that we're getting a list of permissions for
        warn_unknown_perms (bool)

    Returns:
        tuple
        set - all permissions allowed by the policies
        set - all permisisons allowed by the policies not marked with STATEMENT_SKIP_SID
    """
    if not role.policies:
        return set(), set()

    return get_permissions_in_policy(
        role.policies[-1]["Policy"], warn_unknown_perms=warn_unknown_perms
    )


def _get_services_in_permissions(permissions_set: Iterable[str]) -> List[str]:
    """
    Given a set of permissions, return a sorted set of services

    Args:
        permissions_set

    Returns:
        services_set
    """
    services_set = set()
    for permission in permissions_set:
        try:
            service = permission.split(":")[0]
        except IndexError:
            pass
        else:
            services_set.add(service)
    return sorted(services_set)


def partial_update_role_data(
    role: Role,
    dynamo_table: Table,
    account_number: str,
    config: RepokidConfig,
    conn: Dict[str, Any],
    hooks: RepokidHooks,
    source: str,
    add_no_repo: bool = True,
) -> None:
    """
    Perform a scaled down version of role update, this is used to get an accurate count of repoable permissions after
    a rollback or repo.

    Does update:
     - Policies
     - Aardvark data
     - Total permissions
     - Repoable permissions
     - Repoable services
     - Stats

    Does not update:
     - Filters
     - Active/inactive roles

    Args:
        role (Role)
        dynamo_table
        account_number
        config
        conn (dict)
        hooks
        source: repo, rollback, etc
        add_no_repo: if set to True newly discovered permissions will be added to no repo list

    Returns:
        None
    """
    current_policies = get_role_inline_policies(role.dict(), **conn) or {}
    update_role_data(
        dynamo_table,
        account_number,
        role,
        current_policies,
        source=source,
        add_no_repo=add_no_repo,
    )
    aardvark_data = get_aardvark_data(config["aardvark_api_location"], arn=role.arn)

    if not aardvark_data:
        return

    batch_processing = config.get("query_role_data_in_batch", False)
    batch_size = config.get("batch_processing_size", 100)

    role.aa_data = aardvark_data[role.arn]
    _calculate_repo_scores(
        RoleList([role]),
        config["filter_config"]["AgeFilter"]["minimum_age"],
        hooks,
        batch_processing,
        batch_size,
    )
    set_role_data(
        dynamo_table,
        role.role_id,
        {
            "AAData": role.aa_data,
            "TotalPermissions": role.total_permissions,
            "RepoablePermissions": role.repoable_permissions,
            "RepoableServices": role.repoable_services,
        },
    )
    update_stats(dynamo_table, RoleList([role]), source=source)
    # TODO(psanders): return new role instead of mutating
