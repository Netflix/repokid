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

from policyuniverse import all_permissions
from policyuniverse import expand_policy
from policyuniverse import get_actions_from_statement

from repokid.hooks import call_hooks
from repokid.types import RepokidHooks

BEGINNING_OF_2015_MILLI_EPOCH = 1420113600000
IAM_ACCESS_ADVISOR_UNSUPPORTED_SERVICES = frozenset([""])
IAM_ACCESS_ADVISOR_UNSUPPORTED_ACTIONS = frozenset(["iam:passrole"])
STATEMENT_SKIP_SID = "NOREPO"

logger = logging.getLogger("repokid")


# permission decisions have the form repoable - boolean, and decider - string
class RepoablePermissionDecision(object):
    def __init__(self) -> None:
        self.repoable: Optional[bool] = None
        self.decider: str = ""

    def __repr__(self) -> str:
        return "Is repoable: {}, Decider: {}".format(self.repoable, self.decider)


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
    return new_permissions - old_permissions


def convert_repoable_perms_to_perms_and_services(
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


def get_services_and_permissions_from_repoable(
    repoable: List[str],
) -> Tuple[Set[str], Set[str]]:
    repoable_permissions = set()
    repoable_services = set()

    for entry in repoable:
        if len(entry.split(":")) == 2:
            repoable_permissions.add(entry)
        else:
            repoable_services.add(entry)

    return repoable_permissions, repoable_services


def get_repoable_permissions(
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

    hooks_output = call_hooks(
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

    logger.debug(
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
        policy = expand_policy(policy=policy, expand_deny=False) if policy else {}
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
        logger.warning("Unknown permissions found: {}".format(weird_permissions))

    return total_permissions, eligible_permissions


def _get_potentially_repoable_permissions(
    role_name: str,
    account_number: str,
    aa_data: List[Dict[str, Any]],
    permissions: Set[str],
    no_repo_permissions: Dict[str, int],
    minimum_age: int,
) -> Dict[str, Any]:
    ago = datetime.timedelta(minimum_age)
    now = datetime.datetime.now(tz=datetime.timezone.utc)

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
            logger.error(
                "Got malformed Access Advisor data for {role_name} in {account_number} for service {service}"
                ": {last_authenticated}".format(
                    role_name=role_name,
                    account_number=account_number,
                    service=service.get("serviceNamespace"),
                    last_authenticated=service["lastAuthenticated"],
                )
            )
            used_services.add(service["serviceNamespace"])

        accessed_dt = datetime.datetime.fromtimestamp(
            accessed, tz=datetime.timezone.utc
        )
        if accessed_dt > now - ago:
            used_services.add(service["serviceNamespace"])

    for (
        permission_name,
        permission_decision,
    ) in potentially_repoable_permissions.items():
        if permission_name.split(":")[0] in IAM_ACCESS_ADVISOR_UNSUPPORTED_SERVICES:
            logger.debug("skipping {}".format(permission_name))
            continue

        # we have an unused service but need to make sure it's repoable
        if permission_name.split(":")[0] not in used_services:
            if permission_name in IAM_ACCESS_ADVISOR_UNSUPPORTED_ACTIONS:
                logger.debug("skipping {}".format(permission_name))
                continue

            permission_decision.repoable = True
            permission_decision.decider = "Access Advisor"

    return potentially_repoable_permissions


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


def get_repoed_policy(
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
                new_actions = {
                    action
                    for action in statement_actions
                    if action not in repoable_permissions
                    and action.split(":")[0] not in repoable_permissions
                }

                if statement_actions == new_actions:
                    # No permissions are being taken away; let's not modify this statement at all.
                    continue

                # get_actions_from_statement has already inverted this so our new statement should be 'Action'
                if "NotAction" in statement:
                    del statement["NotAction"]

                # by putting this into a set, we lose order, which may be confusing to someone.
                statement["Action"] = sorted(list(new_actions))

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


def get_services_in_permissions(permissions_set: Iterable[str]) -> List[str]:
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
