#     Copyright 2017 Netflix, Inc.
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
from dateutil.tz import tzlocal
import time

from policyuniverse import expand_policy, get_actions_from_statement, all_permissions

from repokid.utils.dynamo import (add_to_end_of_list, get_role_data, role_ids_for_account, set_role_data,
                                  store_initial_role_data)
from repokid import CONFIG as CONFIG
from repokid import LOGGER as LOGGER
import repokid.hooks
from repokid.role import Role

IAM_ACCESS_ADVISOR_UNSUPPORTED_SERVICES = frozenset(['lightsail', 'organizations'])
IAM_ACCESS_ADVISOR_UNSUPPORTED_ACTIONS = frozenset(['iam:passrole'])


def add_new_policy_version(dynamo_table, role, current_policy, update_source):
    """
    Create a new entry in the history of policy versions in Dynamo. The entry contains the source of the new policy:
    (scan, repo, or restore) the current time, and the current policy contents. Updates the role's policies with the
    full policies including the latest.

    Args:
        role (Role)
        current_policy (dict)
        update_source (string): ['Repo', 'Scan', 'Restore']

    Returns:
        None
    """
    policy_entry = {'Source': update_source, 'Discovered': datetime.datetime.utcnow().isoformat(),
                    'Policy': current_policy}

    add_to_end_of_list(dynamo_table, role.role_id, 'Policies', policy_entry)
    role.policies = get_role_data(dynamo_table, role.role_id, fields=['Policies'])['Policies']


def find_and_mark_inactive(dynamo_table, account_number, active_roles):
    """
    Mark roles in the account that aren't currently active inactive. Do this by getting all roles in the account and
    subtracting the active roles, any that are left are inactive and should be marked thusly.

    Args:
        account_number (string)
        active_roles (set): the currently active roles discovered in the most recent scan

    Returns:
        None
    """

    active_roles = set(active_roles)
    known_roles = set(role_ids_for_account(dynamo_table, account_number))
    inactive_roles = known_roles - active_roles

    for roleID in inactive_roles:
        role_dict = get_role_data(dynamo_table, roleID, fields=['Active', 'Arn'])
        if role_dict.get('Active'):
            set_role_data(dynamo_table, roleID, {'Active': False})


def find_newly_added_permissions(old_policy, new_policy):
    """
    Compare and old version of policies to a new version and return a set of permissions that were added.  This will
    be used to maintain a list of permissions that were newly added and should not be repoed for a period of time.

    Args:
        old_policy
        new_policy

    Returns:
        set: Exapnded set of permissions that are in the new policy and not the old one
    """
    old_permissions = _get_role_permissions(Role({'Policies': [{'Policy': old_policy}]}))
    new_permissions = _get_role_permissions(Role({'Policies': [{'Policy': new_policy}]}))
    return new_permissions - old_permissions


def update_no_repo_permissions(dynamo_table, role, newly_added_permissions):
    """
    Update Dyanmo entry for newly added permissions. Any that were newly detected get added with an expiration
    date of now plus the config setting for 'repo_requirements': 'exclude_new_permissions_for_days'. Expired entries
    get deleted. Also update the role object with the new no-repo-permissions.

    Args:
        role
        newly_added_permissions (set)

    Returns:
        None
    """
    current_ignored_permissions = get_role_data(dynamo_table, role.role_id, fields=['NoRepoPermissions']).get(
                                                'NoRepoPermissions', {})
    new_ignored_permissions = {}

    current_time = int(time.time())
    new_perms_expire_time = current_time + (
        24 * 60 * 60 * CONFIG['repo_requirements'].get('exclude_new_permissions_for_days', 14))

    # only copy non-expired items to the new dictionary
    for permission, expire_time in current_ignored_permissions.items():
        if expire_time > current_time:
            new_ignored_permissions[permission] = current_ignored_permissions[permission]

    for permission in newly_added_permissions:
        new_ignored_permissions[permission] = new_perms_expire_time

    role.no_repo_permissions = new_ignored_permissions
    set_role_data(dynamo_table, role.role_id, {'NoRepoPermissions': role.no_repo_permissions})


def update_opt_out(dynamo_table, role):
    """
    Update opt-out object for a role - remove (set to empty dict) any entries that have expired
    Opt-out objects should have the form {'expire': xxx, 'owner': xxx, 'reason': xxx}

    Args:
        role

    Returns:
        None
    """
    if role.opt_out and int(role.opt_out['expire']) < int(time.time()):
        set_role_data(dynamo_table, role.role_id, {'OptOut': {}})


def update_role_data(dynamo_table, account_number, role, current_policy, source='Scan', add_no_repo=True):
    """
    Compare the current version of a policy for a role and what has been previously stored in Dynamo.
      - If current and new policy versions are different store the new version in Dynamo. Add any newly added
          permissions to temporary permission blacklist. Purge any old entries from permission blacklist.
      - Refresh the updated time on the role policy
      - If the role is completely new, store the first version in Dynamo
      - Updates the role with full history of policies, including current version

    Args:
        dynamo_table
        account_number
        role (Role): current role being updated
        current_policy (dict): representation of the current policy version
        source: Default 'Scan' but could be Repo, Rollback, etc

    Returns:
        None
    """

    # policy_entry: source, discovered, policy
    stored_role = get_role_data(dynamo_table, role.role_id, fields=['OptOut', 'Policies'])
    if not stored_role:
        role_dict = store_initial_role_data(dynamo_table, role.arn, role.create_date, role.role_id, role.role_name,
                                            account_number, current_policy)
        role.set_attributes(role_dict)
        LOGGER.info('Added new role ({}): {}'.format(role.role_id, role.arn))
    else:
        # is the policy list the same as the last we had?
        old_policy = stored_role['Policies'][-1]['Policy']
        if current_policy != old_policy:
            add_new_policy_version(dynamo_table, role, current_policy, source)
            LOGGER.info('{} has different inline policies than last time, adding to role store'.format(role.arn))

            newly_added_permissions = find_newly_added_permissions(old_policy, current_policy)
        else:
            newly_added_permissions = set()

        if add_no_repo:
            update_no_repo_permissions(dynamo_table, role, newly_added_permissions)
        update_opt_out(dynamo_table, role)
        set_role_data(dynamo_table, role.role_id, {'Refreshed': datetime.datetime.utcnow().isoformat()})

        cur_role_data = get_role_data(dynamo_table, role.role_id, fields=['OptOut', 'Policies'])
        role.opt_out = cur_role_data.get('OptOut', {})
        role.policies = cur_role_data.get('Policies', [])


def update_stats(dynamo_table, roles, source='Scan'):
    """
    Create a new stats entry for each role in a set of roles and add it to Dynamo

    Args:
        roles (Roles): a list of all the role objects to update data for
        source (string): the source of the new stats data (repo, scan, etc)

    Returns:
        None
    """
    for role in roles:
        new_stats = {'Date': datetime.datetime.utcnow().isoformat(),
                     'DisqualifiedBy': role.disqualified_by,
                     'PermissionsCount': role.total_permissions,
                     'Source': source}
        stats_list = get_role_data(dynamo_table, role.role_id, fields=['Stats']).get('Stats', [])
        try:
            cur_stats = stats_list[-1]
        except IndexError:
            cur_stats = {'DisqualifiedBy': [], 'PermissionsCount': 0}

        for item in ['DisqualifiedBy', 'PermissionsCount']:
            if new_stats[item] != cur_stats[item]:
                add_to_end_of_list(dynamo_table, role.role_id, 'Stats', new_stats)


def _calculate_repo_scores(roles, minimum_age, hooks):
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
    for role in roles:
        permissions = _get_role_permissions(role)

        role.total_permissions = len(permissions)

        # if we don't have any access advisor data for a service than nothing is repoable
        if not role.aa_data:
            LOGGER.info('No data found in access advisor for {}'.format(role.role_id))
            role.repoable_permissions = 0
            role.repoable_services = []
            continue

        # permissions are only repoable if the role isn't being disqualified by filter(s)
        if len(role.disqualified_by) == 0:
            repoable_permissions = _get_repoable_permissions(role.role_name, permissions, role.aa_data,
                                                             role.no_repo_permissions, minimum_age, hooks)
            repoable_services = set([permission.split(':')[0] for permission in repoable_permissions])
            repoable_services = sorted(repoable_services)
            role.repoable_permissions = len(repoable_permissions)
            role.repoable_services = repoable_services
        else:
            role.repoable_permissions = 0
            role.repoable_services = []


def _get_repoable_permissions(role_name, permissions, aa_data, no_repo_permissions, minimum_age, hooks):
    """
    Generate a list of repoable permissions for a role based on the list of all permissions the role's policies
    currently allow and Access Advisor data for the services included in the role's policies.

    The first step is to come up with a list of services that were used within the time threshold (the same defined)
    in the age filter config. Permissions are repoable if they aren't in the used list, aren't in the constant list
    of unsupported services/actions (IAM_ACCESS_ADVISOR_UNSUPPORTED_SERVICES, IAM_ACCESS_ADVISOR_UNSUPPORTED_ACTIONS),
    and aren't being temporarily ignored because they're on the no_repo_permissions list (newly added).

    Args:
        role_name
        permissions (list): The full list of permissions that the role's permissions allow
        aa_data (list): A list of Access Advisor data for a role. Each element is a dictionary with a couple required
                        attributes: lastAuthenticated (epoch time in milliseconds when the service was last used and
                        serviceNamespace (the service used)
        no_repo_permissions (dict): Keys are the name of permissions and values are the time the entry expires
        minimum_age: Minimum age of a role (in days) for it to be repoable
        hooks: Dict containing hook names and functions to run

    Returns:
        set: Permissions that are 'repoable' (not used within the time threshold)
    """
    ago = datetime.timedelta(minimum_age)
    now = datetime.datetime.now(tzlocal())

    current_time = time.time()
    no_repo_list = [perm.lower() for perm in no_repo_permissions if no_repo_permissions[perm] > current_time]

    used_services = set()
    for service in aa_data:
        accessed = service['lastAuthenticated']
        if not accessed:
            continue
        accessed = datetime.datetime.fromtimestamp(accessed / 1000, tzlocal())
        if accessed > now - ago:
            used_services.add(service['serviceNamespace'])

    repoable_permissions = set()
    for permission in permissions:
        if permission.split(':')[0] in IAM_ACCESS_ADVISOR_UNSUPPORTED_SERVICES:
            LOGGER.warn('skipping {}'.format(permission))
            continue

        # we have an unused service but need to make sure it's repoable
        if permission.split(':')[0] not in used_services:
            if permission.lower() in IAM_ACCESS_ADVISOR_UNSUPPORTED_ACTIONS:
                LOGGER.warn('skipping {}'.format(permission))
                continue

            if permission.lower() in no_repo_list:
                LOGGER.info('skipping {} for role {} because it is in the no repo list'.format(permission, role_name))
                continue

            repoable_permissions.add(permission.lower())

    hooks_output = repokid.hooks.call_hooks(hooks, 'DURING_REPOABLE_CALCULATION',
                                            {'role_name': role_name, 'permissions': repoable_permissions,
                                             'aa_data': aa_data, 'no_repo_permissions': no_repo_permissions,
                                             'minimum_age': minimum_age})

    return hooks_output['permissions']


def _get_repoed_policy(policies, repoable_permissions):
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
    for policy_name, policy in role_policies.items():
        # list of indexes in the policy that are empty
        empty_statements = []

        if type(policy['Statement']) is dict:
            policy['Statement'] = [policy['Statement']]

        for idx, statement in enumerate(policy['Statement']):
            if statement['Effect'].lower() == 'allow':
                statement_actions = get_actions_from_statement(statement)
                statement_actions = statement_actions.difference(repoable_permissions)

                # get_actions_from_statement has already inverted this so our new statement should be 'Action'
                if 'NotAction' in statement:
                    del statement['NotAction']

                # by putting this into a set, we lose order, which may be confusing to someone.
                statement['Action'] = sorted(list(statement_actions))

                # mark empty statements to be removed
                if len(statement['Action']) == 0:
                    empty_statements.append(idx)

        # do the actual removal of empty statements
        for idx in sorted(empty_statements, reverse=True):
            del policy['Statement'][idx]

        # mark empty policies to be removed
        if len(policy['Statement']) == 0:
            empty_policies.append(policy_name)

    # do the actual removal of empty policies.
    for policy_name in empty_policies:
        del role_policies[policy_name]

    return role_policies, empty_policies


def _get_role_permissions(role, warn_unknown_perms=False):
    """
    Expand the most recent version of policies from a role to produce a list of all the permissions that are allowed
    (permission is included in one or more statements that is allowed).  To perform expansion the policyuniverse
    library is used. The result is a list of all of the individual permissions that are allowed in any of the
    statements. If our resultant list contains any permissions that aren't listed in the master list of permissions
    we'll raise an exception with the set of unknown permissions found.

    Args:
        role (Role): The role object that we're getting a list of permissions for

    Returns:
        set: A set of permissions that the role has policies that allow
    """
    permissions = set()

    for policy_name, policy in role.policies[-1]['Policy'].items():
        policy = expand_policy(policy=policy, expand_deny=False)
        for statement in policy.get('Statement'):
            if statement['Effect'].lower() == 'allow':
                permissions = permissions.union(get_actions_from_statement(statement))

    weird_permissions = permissions.difference(all_permissions)
    if weird_permissions and warn_unknown_perms:
        LOGGER.warn('Unknown permissions found: {}'.format(weird_permissions))

    return permissions
