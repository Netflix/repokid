#!/usr/bin/env python
"""
Usage:
    repokid config <config_filename>
    repokid update_role_cache <account_number>
    repokid display_role_cache <account_number> [--inactive]
    repokid find_roles_with_permission <permission>
    repokid display_role <account_number> <role_name>
    repokid repo_role <account_number> <role_name> [-c]
    repokid rollback_role <account_number> <role_name> [--selection=NUMBER] [-c]
    repokid repo_all_roles <account_number> [-c]
    repokid repo_stats <output_filename> [--account=ACCOUNT_NUMBER]


Options:
    -h --help       Show this screen
    --version       Show Version
    -c --commit     Actually do things.
"""

__version__ = '0.5'

from cloudaux.aws.iam import list_roles, get_role_inline_policies
from collections import defaultdict
import csv
import datetime
from dateutil.tz import tzlocal
from docopt import docopt
import json
import logging
import os
import pprint
import requests
from utils import roledata
import sys
from tabulate import tabulate
from tqdm import tqdm
from policyuniverse import expand_policy, get_actions_from_statement, all_permissions
import import_string


IAM_ACCESS_ADVISOR_UNSUPPORTED_SERVICES = frozenset([])
IAM_ACCESS_ADVISOR_UNSUPPORTED_ACTIONS = frozenset(['iam:passrole'])

# http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-limits.html
MAX_AWS_POLICY_SIZE = 10240

CUR_ACCOUNT_NUMBER = None
CONFIG = None
LOGGER = None


def _generate_default_config(filename=None):
    config_dict = {
        "filter_config": {
            "AgeFilter": {
                "minimum_age": 90
            },
            "BlacklistFilter": {
                "all": [
                ]
            }
        },

        "active_filters": [
            "repokid.filters.age:AgeFilter",
            "repokid.filters.lambda:LambdaFilter",
            "repokid.filters.blacklist:BlacklistFilter"
        ],

        "aardvark_api_location": "<AARDVARK_API_LOCATION>",

        "connection_iam": {
            "assume_role": "<IAM_ROLE_NAME>",
            "session_name": "repokid",
            "region": "us-east-1"
        },

        "dynamo_db": {
            "assume_role": "Repokid",
            "account_number": "<DYNAMO_TABLE_ACCOUNT_NUMBER>",
            "endpoint": "<DYNAMO_TABLE_ENDPOINT>",
            "region": "<DYNAMO_TABLE_REGION>",
            "session_name": "repokid"
        },

        "logging": {
            "version": 1,
            "disable_existing_loggers": "False",
            "formatters": {
                "standard": {
                    "format": "%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]"
                }
            },
            "handlers": {
                "file": {
                    "class": "logging.handlers.RotatingFileHandler",
                    "level": "INFO",
                    "formatter": "standard",
                    "filename": "repokid.log",
                    "maxBytes": 10485760,
                    "backupCount": 100,
                    "encoding": "utf8"
                },
                "console": {
                    "class": "logging.StreamHandler",
                    "level": "INFO",
                    "formatter": "standard",
                    "stream": "ext://sys.stdout"
                }
            },
            "loggers": {
                "repokid": {
                    "handlers": ["file", "console"],
                    "level": "INFO"
                }
            }
        },
        "repo_requirements": {
            "oldest_aa_data_days": 5
        }
    }
    if filename:
        try:
            with open(filename, 'w') as f:
                json.dump(config_dict, f, indent=4)
        except OSError as e:
            LOGGER.error("Unable to open {} for writing: {}".format(filename, e.message))
        else:
            LOGGER.info("Successfully wrote sample config to {}".format(filename))
    return config_dict


def _init_config():
    global CONFIG
    load_config_paths = [os.path.join(os.getcwd(), 'config.json'),
                         '/etc/repokid/config.json',
                         '/apps/repokid/config.json']
    for path in load_config_paths:
        try:
            with open(path, 'r') as f:
                CONFIG = json.load(f)
                print("Loaded config from {}".format(path))
        except IOError:
            print("Unable to load config from {}, trying next location".format(path))
        else:
            return
    print("Config not found in any path, using defaults")
    CONFIG = _generate_default_config()


def _init_logging():
    global LOGGER
    if not CONFIG:
        _init_config()
    logging.config.dictConfig(CONFIG['logging'])
    LOGGER = logging.getLogger(__name__)


# inspiration from https://github.com/slackhq/python-rtmbot/blob/master/rtmbot/core.py
class FilterPlugins(object):
    def __init__(self):
        self.filter_plugins = []

    def load_plugin(self, module):
        cls = None
        try:
            cls = import_string(module)
        except ImportError as e:
            LOGGER.warn("Unable to find plugin {}, exception: {}".format(module, e))
        else:
            plugin = None
            try:
                plugin = cls(config=CONFIG['filter_config'].get(cls.__name__))
            except KeyError:
                plugin = cls()
            LOGGER.info('Loaded plugin {}'.format(module))
            self.filter_plugins.append(plugin)


class Filter(object):
    def __init__(self, config=None):
        self.config = config

    def apply(self, input_list):
        raise NotImplementedError


WEIRD = set([])


def update_role_cache(account_number):
    conn = CONFIG['connection_iam']
    conn['account_number'] = account_number

    roles = list_roles(**conn)

    active_roles = []
    LOGGER.info('Updating role data for account {}'.format(account_number))
    for role in tqdm(roles):
        role['policies'] = get_role_inline_policies(role, **conn) or {}
        active_roles.append(role['RoleId'])
        roledata.update_role_data(role)

    LOGGER.info('Finding inactive accounts')
    roledata.find_and_mark_inactive(active_roles)

    LOGGER.info('Filtering roles')
    filtered_roles_list = {}
    plugins = FilterPlugins()

    # need to have all roles in the dictionary, even if they aren't filtered
    filtered_roles_list = {role['RoleId']: [] for role in roles}

    for plugin in CONFIG.get('active_filters'):
        plugins.load_plugin(plugin)

    for plugin in plugins.filter_plugins:
        filtered_list = plugin.apply(roles)
        class_name = plugin.__class__.__name__
        for role in filtered_list:
            filtered_roles_list[role['RoleId']].append(class_name)

    roledata.update_filtered_roles(filtered_roles_list)

    LOGGER.info('Getting data from Aardvark')
    aardvark_data = _get_aardvark_data(account_number)

    LOGGER.info('Updating with Aardvark data')
    roledata.update_aardvark_data(account_number, aardvark_data)

    LOGGER.info('Calculating repoable permissions and services')
    roledata.update_repoable_data(_calculate_repo_scores(account_number))

    LOGGER.info('Updating stats')
    roledata.update_stats(source='Scan')


def display_roles(account_number, inactive=False):
    headers = ['Name', 'Disqualified By', 'Can be repoed', 'Permissions', 'Repoable', 'Repoed', 'Services']

    rows = list()

    if inactive:
        roles_data = {roleID: roledata.get_role_data(roleID)
                      for roleID in tqdm(roledata.roles_for_account(account_number))}
    else:
        roles_data = roledata.get_data_for_active_roles_in_account(account_number)

    for roleID, role_data in roles_data.items():
        rows.append([role_data['RoleName'],
                     role_data.get('DisqualifiedBy', []),
                     len(role_data.get('DisqualifiedBy', [])) == 0,
                     role_data['TotalPermissions'],
                     role_data.get('RepoablePermissions', 0),
                     role_data['Repoed'],
                     role_data.get('RepoableServices')])

    rows = sorted(rows, key=lambda x: (x[4], x[0], x[3]))

    print tabulate(rows, headers=headers)
    with open('table.csv', 'wb') as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(headers)
        for row in rows:
            csv_writer.writerow(row)


def _get_role_permissions(role):
    permissions = set()
    for policy_name, policy in _get_current_policies(role).items():
        policy = expand_policy(policy=policy, expand_deny=False)
        for statement in policy.get('Statement'):
            if statement['Effect'].lower() == 'allow':
                permissions = permissions.union(get_actions_from_statement(statement))

    for permission in permissions:
        if permission.startswith('tag:'):
            LOGGER.info('Role {} has {}'.format(role['RoleName'], permission))

    global WEIRD
    weird_permissions = permissions.difference(all_permissions)
    if weird_permissions:
        WEIRD = WEIRD.union(weird_permissions)

    return permissions


def _get_repoable_permissions(permissions, role_data):
    ago = datetime.timedelta(CONFIG['filter_config']['AgeFilter']['minimum_age'])
    now = datetime.datetime.now(tzlocal())

    used_services = set()
    for service in role_data.get('AAData', []):
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

        if permission.split(':')[0] not in used_services:
            if permission.lower() in IAM_ACCESS_ADVISOR_UNSUPPORTED_ACTIONS:
                LOGGER.warn('skipping {}'.format(permission))
                continue

            repoable_permissions.add(permission.lower())

    return repoable_permissions


def find_roles_with_permission(permission):
    for roleID in roledata.role_ids_for_all_accounts():
        role_data = roledata.get_role_data(roleID)
        permissions = _get_role_permissions(role_data)
        if permission in permissions:
            LOGGER.info('ARN {arn} has {permission}'.format(arn=role_data['Arn'], permission=permission))


def _get_current_policies(role_dict):
    return role_dict['Policies'][-1].get('Policy')


def _calculate_repo_scores(account_number):
    roles_data = roledata.get_data_for_active_roles_in_account(account_number)

    repoable_data = defaultdict(dict)

    for roleID, role_data in roles_data.items():
        permissions = _get_role_permissions(role_data)
        repoable_data[roleID]['TotalPermissions'] = len(permissions)

        if not role_data.get('AAData', {}):
            LOGGER.info('No data found in access advisor for {}'.format(roleID))
            repoable_data[roleID]['RepoablePermissions'] = 0
            repoable_data[roleID]['RepoableServices'] = []
            continue

        # Dynamo won't store empty lists, so if the list is empty it won't be stored
        if len(role_data.get('DisqualifiedBy', [])) == 0:
            repoable_permissions = _get_repoable_permissions(permissions, role_data)
            repoable_services = set([permission.split(':')[0] for permission in repoable_permissions])
            repoable_services = sorted(repoable_services)
            repoable_data[roleID]['RepoablePermissions'] = len(repoable_permissions)
            repoable_data[roleID]['RepoableServices'] = repoable_services
        else:
            repoable_data[roleID]['RepoablePermissions'] = 0
            repoable_data[roleID]['RepoableServices'] = []

    if WEIRD:
        all_services = set([permission.split(':')[0] for permission in all_permissions])
        # print('Not sure about these permissions:\n{}'.format(json.dumps(list(WEIRD), indent=2, sort_keys=True)))
        weird_services = set([permission.split(':')[0] for permission in WEIRD])
        weird_services = weird_services.difference(all_services)
        LOGGER.warn('Not sure about these services:\n{}'.format(json.dumps(list(weird_services), indent=2,
                    sort_keys=True)))

    return repoable_data


def _get_repoed_policy(role, repoable_permissions):
    """
    Iterate over role policies.
    Iterate over policy statements.
    Skip Deny statements.
    Remove any actions that are in repoable_permissions.
    Remove any statements that now have zero actions.
    Remove any policies that now have zero statements.
    return
    """
    # work with our own copy; don't mess with the CACHE copy.
    role_policies = dict(role['Policies'][-1]['Policy'])

    empty_policies = []
    for policy_name, policy in role_policies.items():
        empty_statements = []
        if type(policy['Statement']) is dict:
            policy['Statement'] = [policy['Statement']]
        for idx, statement in enumerate(policy['Statement']):
            if statement['Effect'].lower() == 'allow':
                statement_actions = get_actions_from_statement(statement)
                statement_actions = statement_actions.difference(repoable_permissions)
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


def display_role(account_number, role_name):
    """
    Repo status
    Permission Count
    Repo Permission Count
    Enumerate Permissions
    Policy history
    Repoable permissions (from Access Advisor)
    Permissions stats
    """
    role_data = _find_role_in_cache(role_name)
    if not role_data:
        LOGGER.warn('Could not find role with name {}'.format(role_name))
        return

    print "\n\nRole repo data:"
    headers = ['Name', 'Disqualified By', 'Can be repoed', 'Permissions', 'Repoable', 'Repoed', 'Services']
    rows = [[role_data['RoleName'],
             role_data.get('DisqualifiedBy', []),
             len(role_data.get('DisqualifiedBy', [])) == 0,
             role_data['TotalPermissions'],
             role_data.get('RepoablePermissions', 0),
             role_data['Repoed'],
             role_data.get('RepoableServices')]]
    print tabulate(rows, headers=headers) + '\n\n'

    print "Policy history:"
    headers = ['Number', 'Source', 'Discovered', 'Policy Length', 'Policy Contents']
    rows = []
    for index, policies_version in enumerate(role_data['Policies']):
        rows.append([index, policies_version['Source'], policies_version['Discovered'],
                    len(str(policies_version['Policy'])),
                    str(policies_version['Policy'])[:50]])
    print tabulate(rows, headers=headers) + '\n\n'

    print "Stats:"
    headers = ['Date', 'Event Type', 'Permissions Count', 'Disqualified By']
    rows = []
    for stats_entry in role_data.get('Stats', []):
        rows.append([stats_entry['Date'],
                     stats_entry['Source'],
                     stats_entry['PermissionsCount'],
                     stats_entry.get('DisqualifiedBy', [])])
    print tabulate(rows, headers=headers) + '\n\n'

    # can't do anymore if we don't have AA data
    aa_data = role_data.get('AAData', '')
    if not aa_data:
        LOGGER.warn('ARN not found in Access Advisor: {}'.format(role_data['Arn']))
        return

    repoable_permissions = set([])
    permissions = _get_role_permissions(role_data)
    if len(role_data.get('DisqualifiedBy', [])) == 0:
        repoable_permissions = _get_repoable_permissions(permissions, role_data)

    print "Repoable services:"
    headers = ['Service', 'Action', 'Repoable']
    rows = []
    for permission in permissions:
        service = permission.split(':')[0]
        action = permission.split(':')[1]
        repoable = permission in repoable_permissions
        rows.append([service, action, repoable])

    rows = sorted(rows, key=lambda x: (x[2], x[0], x[1]))
    print tabulate(rows, headers=headers) + '\n\n'

    repoed_policies, _ = _get_repoed_policy(role_data, repoable_permissions)

    if repoed_policies:
        print('Repo\'d Policies: \n{}'.format(json.dumps(repoed_policies, indent=2, sort_keys=True)))
    else:
        print('All Policies Removed')

    # need to check if all policies would be too large
    if len(json.dumps(repoed_policies)) > MAX_AWS_POLICY_SIZE:
        LOGGER.error("Policies would exceed the AWS size limit after repo for role: {}.  "
                     "Please manually minify.".format(role_name))


def _get_aardvark_data(account_number):
    response_data = {}

    PAGE_SIZE = 1000
    page_num = 1

    try:
        aardvark_api_location = CONFIG['aardvark_api_location']
    except KeyError:
        LOGGER.error("Unable to find aardvark_api_location in config")
        sys.exit(1)

    payload = {'phrase': '{}'.format(account_number)}
    while True:
        params = {'count': PAGE_SIZE, 'page': page_num}
        try:
            r_aardvark = requests.post(aardvark_api_location, params=params, json=payload)
        except requests.exceptions.RequestException as e:
            LOGGER.error('Request while getting Aardvark data exception: {}').format(e)
            sys.exit(1)
        else:
            response_data.update(r_aardvark.json())
            # don't want these in our Aardvark data
            response_data.pop('count')
            response_data.pop('page')
            response_data.pop('total')
            if PAGE_SIZE * page_num < r_aardvark.json().get('total'):
                page_num += 1
            else:
                break
    return response_data


def repo_all_roles(account_number, commit=False):
    for _, role in roledata.get_data_for_active_roles_in_account(account_number).items():
        repo_role(account_number, role['RoleName'], commit=commit)
    LOGGER.info('Done')


def _find_role_in_cache(role_name):
    """Return a tuple with arn and role from cache matching supplied rolename or None, None"""
    found = False

    for roleID in roledata.roles_for_account(CUR_ACCOUNT_NUMBER):
        role_data = roledata.get_role_data(roleID)
        if role_data['RoleName'].lower() == role_name.lower():
            found = True
            break

    if found:
        return role_data
    else:
        return None


def repo_role(account_number, role_name, commit=False):
    role_data = _find_role_in_cache(role_name)
    if not role_data:
        LOGGER.error('Could not find role with name {}'.format(role_name))
        return

    disqualified_by = role_data.get('DisqualifiedBy', [])
    if len(disqualified_by) > 0:
        LOGGER.info('Cannot repo role {} because it is being disqualified by: {}'.format(role_name, disqualified_by))
        return

    if 'AAData' not in role_data:
        LOGGER.warn('ARN not found in Access Advisor: {}'.format(role_data['Arn']))
        return

    old_aa_data_services = []
    for aa_service in role_data['AAData']:
        if(datetime.datetime.strptime(aa_service['lastUpdated'], '%a, %d %B %Y %H:%M:%S %Z') <
           datetime.datetime.now() - datetime.timedelta(days=CONFIG['repo_requirements']['oldest_aa_data_days'])):
            old_aa_data_services.append(aa_service['serviceName'])
    if old_aa_data_services:
        LOGGER.error('AAData older than threshold for these services: {}'.format(old_aa_data_services))
        return

    permissions = _get_role_permissions(role_data)
    repoable_permissions = _get_repoable_permissions(permissions, role_data)
    repoed_policies, deleted_policy_names = _get_repoed_policy(role_data, repoable_permissions)

    policies_length = len(json.dumps(repoed_policies))
    if not commit:
        for name in deleted_policy_names:
            LOGGER.info('Would delete policy from {} with name {}'.format(role_name, name))
        if repoed_policies:
            LOGGER.info('Would replace policies for role {} with: \n{}'.format(role_name, json.dumps(repoed_policies,
                        indent=2, sort_keys=True)))
        if policies_length > MAX_AWS_POLICY_SIZE:
            LOGGER.error("Policies would exceed the AWS size limit after repo for role: {}.  "
                         "Please manually minify.".format(role_name))
        return

    from cloudaux import CloudAux
    conn = CONFIG['connection_iam']
    conn['account_number'] = account_number
    ca = CloudAux(**conn)

    if policies_length > MAX_AWS_POLICY_SIZE:
        LOGGER.error("Policies would exceed the AWS size limit after repo for role: {}.  "
                     "Please manually minify.".format(role_name))
        return

    for name in deleted_policy_names:
        LOGGER.info('Deleting policy with name {} from {}'.format(name, role_data['RoleName']))
        ca.call('iam.client.delete_role_policy', RoleName=role_data['RoleName'], PolicyName=name)

    if repoed_policies:
        LOGGER.info('Replacing Policies With: \n{}'.format(json.dumps(repoed_policies, indent=2, sort_keys=True)))
        for policy_name, policy in repoed_policies.items():
            try:
                ca.call('iam.client.put_role_policy', RoleName=role_data['RoleName'], PolicyName=policy_name,
                        PolicyDocument=json.dumps(policy, indent=2, sort_keys=True))
            except Exception as e:
                LOGGER.error('Exception calling PutRolePolicy on {role}/{policy}\n{e}\n'.format(
                             role=role_data['RoleName'], policy=policy_name, e=str(e)))
                return

    role_data['policies'] = get_role_inline_policies(role_data, **conn) or {}
    roledata.add_new_policy_version(role_data, 'Repo')
    roledata.set_repoed(role_data['RoleId'])

    # update total permissions count for stats
    permissions_count = len(_get_role_permissions(role_data))
    roledata.update_total_permissions(role_data['RoleId'], permissions_count)

    roledata.update_stats(source='Repo', roleID=role_data['RoleId'])

    LOGGER.info('Successfully repoed role: {}'.format(role_data['RoleName']))


def rollback_role(account_number, role_name, selection=None, commit=None):
    role_data = _find_role_in_cache(role_name)
    if not role_data:
        LOGGER.error("Couldn't find role ({}) in cache".format(role_name))
        return

    # no option selected, display a table of options
    if not selection:
        headers = ['Number', 'Source', 'Discovered', 'Policy Length', 'Policy Contents']
        rows = []
        for index, policies_version in enumerate(role_data['Policies']):
            rows.append([index, policies_version['Source'], policies_version['Discovered'],
                        len(str(policies_version['Policy'])),
                        str(policies_version['Policy'])[:50]])
        print tabulate(rows, headers=headers)
        return

    from cloudaux import CloudAux
    conn = CONFIG['connection_iam']
    conn['account_number'] = account_number
    ca = CloudAux(**conn)

    current_policies = get_role_inline_policies(role_data, **conn)

    if selection and not commit:
        pp = pprint.PrettyPrinter()
        print "Will restore the following policies:"
        pp.pprint(role_data['Policies'][int(selection)]['Policy'])
        print "Current policies:"
        pp.pprint(current_policies)
        return

    # if we're restoring from a version with fewer policies than we have now, we need to remove them to
    # complete the restore.  To do so we'll store all the policy names we currently have and remove them
    # from the list as we update.  Any policy names left need to be manually removed
    policies_to_remove = current_policies.keys()

    for policy_name, policy in role_data['Policies'][int(selection)]['Policy'].items():
        try:
            LOGGER.info("Pushing cached policy: {}".format(policy_name))
            ca.call('iam.client.put_role_policy', RoleName=role_data['RoleName'], PolicyName=policy_name,
                    PolicyDocument=json.dumps(policy, indent=2, sort_keys=True))
        except Exception as e:
            LOGGER.error("Unable to push policy {}.  Error: {}".format(policy_name, e.message))
        else:
            # remove the policy name if it's in the list
            try:
                policies_to_remove.remove(policy_name)
            except:
                pass

    if policies_to_remove:
        for policy_name in policies_to_remove:
            try:
                ca.call('iam.client.delete_role_policy', RoleName=role_data['RoleName'], PolicyName=policy_name)
            except Exception as e:
                LOGGER.error("Unable to delete policy {}.  Error: {}".format(policy_name, e.message))

    role_data['policies'] = get_role_inline_policies(role_data, **conn) or {}
    roledata.add_new_policy_version(role_data, 'Restore')
    LOGGER.info('Successfully restored selected version of role policies')


def repo_stats(output_file, account_number=None):
    roleIDs = roledata.roles_for_account(account_number) if account_number else roledata.role_ids_for_all_accounts()
    headers = ['RoleId', 'Role Name', 'Account', 'Date', 'Source', 'Permissions Count', 'Disqualified By']
    rows = []

    for roleID in roleIDs:
        role_data = roledata.get_role_data(roleID)
        for stats_entry in role_data.get('Stats', []):
            rows.append([role_data['RoleId'], role_data['RoleName'], role_data['Account'], stats_entry['Date'],
                         stats_entry['Source'], stats_entry['PermissionsCount'],
                         stats_entry.get('DisqualifiedBy', [])])

    try:
        with open(output_file, 'wb') as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(headers)
            for row in rows:
                csv_writer.writerow(row)
    except IOError as e:
        LOGGER.error('Unable to write file {}: {}'.format(output_file, e))
    else:
        LOGGER.info('Successfully wrote stats to {}'.format(output_file))


def main():
    args = docopt(__doc__, version='Repokid {version}'.format(version=__version__))
    _init_logging()

    if args.get('config'):
        config_filename = args.get('<config_filename>')
        return _generate_default_config(filename=config_filename)

    account_number = args.get('<account_number>')
    _init_config()
    global CUR_ACCOUNT_NUMBER
    CUR_ACCOUNT_NUMBER = account_number
    roledata.dynamo_get_or_create_table(**CONFIG['dynamo_db'])

    if args.get('update_role_cache'):
        return update_role_cache(account_number)

    if args.get('display_role_cache'):
        inactive = args.get('--inactive')
        return display_roles(account_number, inactive=inactive)

    if args.get('find_roles_with_permission'):
        return find_roles_with_permission(args.get('<permission>'))

    if args.get('display_role'):
        role_name = args.get('<role_name>')
        return display_role(account_number, role_name)

    if args.get('repo_role'):
        role_name = args.get('<role_name>')
        commit = args.get('--commit')
        return repo_role(account_number, role_name, commit=commit)

    if args.get('rollback_role'):
        role_name = args.get('<role_name>')
        commit = args.get('--commit')
        selection = args.get('--selection')
        return rollback_role(account_number, role_name, selection=selection, commit=commit)

    if args.get('repo_all_roles'):
        commit = args.get('--commit')
        return repo_all_roles(account_number, commit=commit)

    if args.get('repo_stats'):
        output_file = args.get('<output_filename>')
        account_number = args.get('--account')
        return repo_stats(output_file, account_number=account_number)


if __name__ == '__main__':
    main()
