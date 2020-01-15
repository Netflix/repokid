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
"""
Usage:
    repokid config <config_filename>
    repokid update_role_cache <account_number>
    repokid display_role_cache <account_number> [--inactive]
    repokid find_roles_with_permissions <permission>... [--output=ROLE_FILE]
    repokid remove_permissions_from_roles --role-file=ROLE_FILE <permission>... [-c]
    repokid display_role <account_number> <role_name>
    repokid schedule_repo <account_number>
    repokid repo_role <account_number> <role_name> [-c]
    repokid rollback_role <account_number> <role_name> [--selection=NUMBER] [-c]
    repokid repo_all_roles <account_number> [-c]
    repokid show_scheduled_roles <account_number>
    repokid cancel_scheduled_repo <account_number> [--role=ROLE_NAME] [--all]
    repokid repo_scheduled_roles <account_number> [-c]
    repokid repo_stats <output_filename> [--account=ACCOUNT_NUMBER]


Options:
    -h --help       Show this screen
    --version       Show Version
    -c --commit     Actually do things.
"""

import csv
import datetime
from datetime import datetime as dt
import json
import pprint
import re
import sys
import time

import botocore
from cloudaux.aws.iam import (
    delete_role_policy,
    get_account_authorization_details,
    get_role_inline_policies,
    put_role_policy,
)
from cloudaux.aws.sts import sts_conn
from docopt import docopt
import import_string
from policyuniverse.arn import ARN
from repokid import __version__ as __version__
from repokid import _get_hooks
from repokid import CONFIG
from repokid import LOGGER
import repokid.hooks
from repokid.role import Role, Roles
from repokid.utils.dynamo import (
    dynamo_get_or_create_table,
    find_role_in_cache,
    get_role_data,
    role_ids_for_account,
    role_ids_for_all_accounts,
    set_role_data,
)
import repokid.utils.roledata as roledata
import requests
from tabulate import tabulate
import tabview as t
from tqdm import tqdm


# http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-limits.html
MAX_AWS_POLICY_SIZE = 10240


def _generate_default_config(filename=None):
    """
    Generate and return a config dict; will write the config to a file if a filename is provided

    Args:
        filename (string): Name of file to write the generated config (represented in JSON)

    Returns:
        dict: Template for Repokid config as a dictionary
    """
    config_dict = {
        "query_role_data_in_batch": False,
        "batch_processing_size": 100,
        "filter_config": {
            "AgeFilter": {"minimum_age": 90},
            "BlocklistFilter": {
                "all": [],
                "blocklist_bucket": {
                    "bucket": "<BLOCKLIST_BUCKET>",
                    "key": "<PATH/blocklist.json>",
                    "account_number": "<S3_blocklist_account>",
                    "region": "<S3_blocklist_region",
                    "assume_role": "<S3_blocklist_assume_role>",
                },
            },
            "ExclusiveFilter": {
                "all": ["<GLOB_PATTERN>"],
                "<ACCOUNT_NUMBER>": ["<GLOB_PATTERN>"],
            },
        },
        "active_filters": [
            "repokid.filters.age:AgeFilter",
            "repokid.filters.lambda:LambdaFilter",
            "repokid.filters.blocklist:BlocklistFilter",
            "repokid.filters.optout:OptOutFilter",
        ],
        "aardvark_api_location": "<AARDVARK_API_LOCATION>",
        "connection_iam": {
            "assume_role": "RepokidRole",
            "session_name": "repokid",
            "region": "us-east-1",
        },
        "dynamo_db": {
            "assume_role": "RepokidRole",
            "account_number": "<DYNAMO_TABLE_ACCOUNT_NUMBER>",
            "endpoint": "<DYNAMO_TABLE_ENDPOINT>",
            "region": "<DYNAMO_TABLE_REGION>",
            "session_name": "repokid",
        },
        "hooks": ["repokid.hooks.loggers"],
        "logging": {
            "version": 1,
            "disable_existing_loggers": "False",
            "formatters": {
                "standard": {
                    "format": "%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]"
                },
                "json": {"class": "repokid.utils.logging.JSONFormatter"},
            },
            "handlers": {
                "file": {
                    "class": "logging.handlers.RotatingFileHandler",
                    "level": "INFO",
                    "formatter": "standard",
                    "filename": "repokid.log",
                    "maxBytes": 10485760,
                    "backupCount": 100,
                    "encoding": "utf8",
                },
                "json_file": {
                    "class": "logging.handlers.RotatingFileHandler",
                    "level": "INFO",
                    "formatter": "json",
                    "filename": "repokid.json",
                    "maxBytes": 10485760,
                    "backupCount": 100,
                    "encoding": "utf8",
                },
                "console": {
                    "class": "logging.StreamHandler",
                    "level": "INFO",
                    "formatter": "standard",
                    "stream": "ext://sys.stdout",
                },
            },
            "loggers": {
                "repokid": {
                    "handlers": ["file", "json_file", "console"],
                    "level": "INFO",
                }
            },
        },
        "opt_out_period_days": 90,
        "dispatcher": {
            "session_name": "repokid",
            "region": "us-west-2",
            "to_rr_queue": "COMMAND_QUEUE_TO_REPOKID_URL",
            "from_rr_sns": "RESPONSES_FROM_REPOKID_SNS_ARN",
        },
        "repo_requirements": {
            "oldest_aa_data_days": 5,
            "exclude_new_permissions_for_days": 14,
        },
        "repo_schedule_period_days": 7,
        "warnings": {"unknown_permissions": False},
    }
    if filename:
        try:
            with open(filename, "w") as f:
                json.dump(config_dict, f, indent=4, sort_keys=True)
        except OSError as e:
            print("Unable to open {} for writing: {}".format(filename, e.message))
        else:
            print("Successfully wrote sample config to {}".format(filename))
    return config_dict


def _get_aardvark_data(aardvark_api_location, account_number=None, arn=None):
    """
    Make a request to the Aardvark server to get all data about a given account or ARN.
    We'll request in groups of PAGE_SIZE and check the current count to see if we're done. Keep requesting as long as
    the total count (reported by the API) is greater than the number of pages we've received times the page size.  As
    we go, keeping building the dict and return it when done.

    Args:
        aardvark_api_location
        account_number (string): Used to form the phrase query for Aardvark so we only get data for the account we want
        arn (string)

    Returns:
        dict: Aardvark data is a dict with the role ARN as the key and a list of services as value
    """
    response_data = {}

    PAGE_SIZE = 1000
    page_num = 1

    if account_number:
        payload = {"phrase": "{}".format(account_number)}
    elif arn:
        payload = {"arn": [arn]}
    else:
        return
    while True:
        params = {"count": PAGE_SIZE, "page": page_num}
        try:
            r_aardvark = requests.post(
                aardvark_api_location, params=params, json=payload
            )
        except requests.exceptions.RequestException as e:
            LOGGER.error("Unable to get Aardvark data: {}".format(e))
            sys.exit(1)
        else:
            if r_aardvark.status_code != 200:
                LOGGER.error("Unable to get Aardvark data")
                sys.exit(1)

            response_data.update(r_aardvark.json())
            # don't want these in our Aardvark data
            response_data.pop("count")
            response_data.pop("page")
            response_data.pop("total")
            if PAGE_SIZE * page_num < r_aardvark.json().get("total"):
                page_num += 1
            else:
                break
    return response_data


@sts_conn("iam")
def _update_repoed_description(role_name, client=None):
    description = None
    try:
        description = client.get_role(RoleName=role_name)["Role"].get("Description", "")
    except KeyError:
        return
    date_string = datetime.datetime.utcnow().strftime("%m/%d/%y")
    if "; Repokid repoed" in description:
        new_description = re.sub(
            r"; Repokid repoed [0-9]{2}\/[0-9]{2}\/[0-9]{2}",
            "; Repokid repoed {}".format(date_string),
            description,
        )
    else:
        new_description = description + " ; Repokid repoed {}".format(date_string)
    # IAM role descriptions have a max length of 1000, if our new length would be longer, skip this
    if len(new_description) < 1000:
        client.update_role_description(RoleName=role_name, Description=new_description)
    else:
        LOGGER.error(
            "Unable to set repo description ({}) for role {}, length would be too long".format(
                new_description, role_name
            )
        )


def _update_role_data(
    role, dynamo_table, account_number, config, conn, hooks, source, add_no_repo=True
):
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
        conn (dict)
        source: repo, rollback, etc
        add_no_repo: if set to True newly discovered permissions will be added to no repo list

    Returns:
        None
    """
    current_policies = get_role_inline_policies(role.as_dict(), **conn) or {}
    roledata.update_role_data(
        dynamo_table,
        account_number,
        role,
        current_policies,
        source=source,
        add_no_repo=add_no_repo,
    )
    aardvark_data = _get_aardvark_data(config["aardvark_api_location"], arn=role.arn)

    if not aardvark_data:
        return

    batch_processing = config.get("query_role_data_in_batch", False)
    batch_size = config.get("batch_processing_size", 100)

    role.aa_data = aardvark_data[role.arn]
    roledata._calculate_repo_scores(
        [role],
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
    roledata.update_stats(dynamo_table, [role], source=source)


# inspiration from https://github.com/slackhq/python-rtmbot/blob/master/rtmbot/core.py
class FilterPlugins(object):
    """
    FilterPlugins is used to hold a list of instantiated plugins. The internal object filter_plugins contains a list
    of active plugins that can be iterated.
    """

    def __init__(self):
        """Initialize empty list"""
        self.filter_plugins = []

    def load_plugin(self, module, config=None):
        """Import a module by path, instantiate it with plugin specific config and add to the list of active plugins"""
        cls = None
        try:
            cls = import_string(module)
        except ImportError as e:
            LOGGER.warn("Unable to find plugin {}, exception: {}".format(module, e))
        else:
            plugin = None
            try:
                plugin = cls(config=config)
            except KeyError:
                plugin = cls()
            LOGGER.info("Loaded plugin {}".format(module))
            self.filter_plugins.append(plugin)


class Filter(object):
    """Base class for filter plugins to inherit.  Passes config if supplied and requires the apply method be defined"""

    def __init__(self, config=None):
        self.config = config

    def apply(self, input_list):
        raise NotImplementedError


def update_role_cache(account_number, dynamo_table, config, hooks):
    """
    Update data about all roles in a given account:
      1) list all the roles and initiate a role object with basic data including name and roleID
      2) get inline policies for each of the roles
      3) build a list of active roles - we'll want to keep data about roles that may have been deleted in case we
         need to restore them, so if we used to have a role and now we don't see it we'll mark it inactive
      4) update data about the roles in Dynamo
      5) mark inactive roles in Dynamo
      6) load and instantiate filter plugins
      7) for each filter determine the list of roles that it filters
      8) update data in Dynamo about filters
      9) get Aardvark data for each role
      10) update Dynamo with Aardvark data
      11) calculate repoable permissions/policies for all the roles
      12) update Dynamo with information about how many total and repoable permissions and which services are repoable
      13) update stats in Dynamo with basic information like total permissions and which filters are applicable

    Args:
        account_number (string): The current account number Repokid is being run against

    Returns:
        None
    """
    conn = config["connection_iam"]
    conn["account_number"] = account_number

    LOGGER.info(
        "Getting current role data for account {} (this may take a while for large accounts)".format(
            account_number
        )
    )

    role_data = get_account_authorization_details(filter="Role", **conn)
    role_data_by_id = {item["RoleId"]: item for item in role_data}

    # convert policies list to dictionary to maintain consistency with old call which returned a dict
    for _, data in role_data_by_id.items():
        data["RolePolicyList"] = {
            item["PolicyName"]: item["PolicyDocument"]
            for item in data["RolePolicyList"]
        }

    roles = Roles([Role(rd) for rd in role_data])

    active_roles = []
    LOGGER.info("Updating role data for account {}".format(account_number))
    for role in tqdm(roles):
        role.account = account_number
        current_policies = role_data_by_id[role.role_id]["RolePolicyList"]
        active_roles.append(role.role_id)
        roledata.update_role_data(dynamo_table, account_number, role, current_policies)

    LOGGER.info("Finding inactive roles in account {}".format(account_number))
    roledata.find_and_mark_inactive(dynamo_table, account_number, active_roles)

    LOGGER.info("Filtering roles")
    plugins = FilterPlugins()

    # Blocklist needs to know the current account
    filter_config = config["filter_config"]
    blocklist_filter_config = filter_config.get(
        "BlocklistFilter", filter_config.get("BlacklistFilter")
    )
    blocklist_filter_config["current_account"] = account_number

    for plugin_path in config.get("active_filters"):
        plugin_name = plugin_path.split(":")[1]
        if plugin_name == "ExclusiveFilter":
            # ExclusiveFilter plugin active; try loading its config. Also, it requires the current account, so add it.
            exclusive_filter_config = filter_config.get("ExclusiveFilter", {})
            exclusive_filter_config["current_account"] = account_number
        plugins.load_plugin(
            plugin_path, config=config["filter_config"].get(plugin_name, None)
        )

    for plugin in plugins.filter_plugins:
        filtered_list = plugin.apply(roles)
        class_name = plugin.__class__.__name__
        for filtered_role in filtered_list:
            LOGGER.info(
                "Role {} filtered by {}".format(filtered_role.role_name, class_name)
            )
            filtered_role.disqualified_by.append(class_name)

    for role in roles:
        set_role_data(
            dynamo_table, role.role_id, {"DisqualifiedBy": role.disqualified_by}
        )

    LOGGER.info("Getting data from Aardvark for account {}".format(account_number))
    aardvark_data = _get_aardvark_data(
        config["aardvark_api_location"], account_number=account_number
    )

    LOGGER.info(
        "Updating roles with Aardvark data in account {}".format(account_number)
    )
    for role in roles:
        try:
            role.aa_data = aardvark_data[role.arn]
        except KeyError:
            LOGGER.warning(
                "Aardvark data not found for role: {} ({})".format(
                    role.role_id, role.role_name
                )
            )
        else:
            set_role_data(dynamo_table, role.role_id, {"AAData": role.aa_data})

    LOGGER.info(
        "Calculating repoable permissions and services for account {}".format(
            account_number
        )
    )

    batch_processing = config.get("query_role_data_in_batch", False)
    batch_size = config.get("batch_processing_size", 100)
    roledata._calculate_repo_scores(
        roles,
        config["filter_config"]["AgeFilter"]["minimum_age"],
        hooks,
        batch_processing,
        batch_size,
    )
    for role in roles:
        LOGGER.debug(
            "Role {} in account {} has\nrepoable permissions: {}\nrepoable services: {}".format(
                role.role_name,
                account_number,
                role.repoable_permissions,
                role.repoable_services,
            )
        )
        set_role_data(
            dynamo_table,
            role.role_id,
            {
                "TotalPermissions": role.total_permissions,
                "RepoablePermissions": role.repoable_permissions,
                "RepoableServices": role.repoable_services,
            },
        )

    LOGGER.info("Updating stats in account {}".format(account_number))
    roledata.update_stats(dynamo_table, roles, source="Scan")


def display_roles(account_number, dynamo_table, inactive=False):
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

    rows = list()

    roles = Roles(
        [
            Role(get_role_data(dynamo_table, roleID))
            for roleID in tqdm(role_ids_for_account(dynamo_table, account_number))
        ]
    )

    if not inactive:
        roles = roles.filter(active=True)

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


def find_roles_with_permissions(permissions, dynamo_table, output_file):
    """
    Search roles in all accounts for a policy with any of the provided permissions, log the ARN of each role.

    Args:
        permissions (list[string]): The name of the permissions to find
        output_file (string): filename to write the output

    Returns:
        None
    """
    arns = list()
    for roleID in role_ids_for_all_accounts(dynamo_table):
        role = Role(
            get_role_data(
                dynamo_table, roleID, fields=["Policies", "RoleName", "Arn", "Active"]
            )
        )
        role_permissions, _ = roledata._get_role_permissions(role)

        permissions = set([p.lower() for p in permissions])
        found_permissions = permissions.intersection(role_permissions)

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

    LOGGER.info('Ouput written to file "{output_file}"'.format(output_file=output_file))


def display_role(account_number, role_name, dynamo_table, config, hooks):
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
    role_id = find_role_in_cache(dynamo_table, account_number, role_name)
    if not role_id:
        LOGGER.warn("Could not find role with name {}".format(role_name))
        return

    role = Role(get_role_data(dynamo_table, role_id))

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
        LOGGER.warn("ARN not found in Access Advisor: {}".format(role.arn))
        return

    warn_unknown_permissions = config.get("warnings", {}).get(
        "unknown_permissions", False
    )
    repoable_permissions = set([])

    permissions, eligible_permissions = roledata._get_role_permissions(
        role, warn_unknown_perms=warn_unknown_permissions
    )
    if len(role.disqualified_by) == 0:
        repoable_permissions = roledata._get_repoable_permissions(
            account_number,
            role.role_name,
            eligible_permissions,
            role.aa_data,
            role.no_repo_permissions,
            config["filter_config"]["AgeFilter"]["minimum_age"],
            hooks,
        )

    print("Repoable services and permissions")
    headers = ["Service", "Action", "Repoable"]
    rows = []
    for permission in permissions:
        service = permission.split(":")[0]
        action = permission.split(":")[1]
        repoable = permission in repoable_permissions
        rows.append([service, action, repoable])

    rows = sorted(rows, key=lambda x: (x[2], x[0], x[1]))
    print(tabulate(rows, headers=headers) + "\n\n")

    repoed_policies, _ = roledata._get_repoed_policy(
        role.policies[-1]["Policy"], repoable_permissions
    )

    if repoed_policies:
        print(
            "Repo'd Policies: \n{}".format(
                json.dumps(repoed_policies, indent=2, sort_keys=True)
            )
        )
    else:
        print("All Policies Removed")

    # need to check if all policies would be too large
    if _inline_policies_size_exceeds_maximum(repoed_policies):
        LOGGER.warning(
            "Policies would exceed the AWS size limit after repo for role: {}.  "
            "Please manually minify.".format(role_name)
        )


def schedule_repo(account_number, dynamo_table, config, hooks):
    """
    Schedule a repo for a given account.  Schedule repo for a time in the future (default 7 days) for any roles in
    the account with repoable permissions.
    """
    scheduled_roles = []

    roles = Roles(
        [
            Role(get_role_data(dynamo_table, roleID))
            for roleID in tqdm(role_ids_for_account(dynamo_table, account_number))
        ]
    )

    scheduled_time = int(time.time()) + (
        86400 * config.get("repo_schedule_period_days", 7)
    )
    for role in roles:
        if role.repoable_permissions > 0 and not role.repo_scheduled:
            role.repo_scheduled = scheduled_time
            # freeze the scheduled perms to whatever is repoable right now
            set_role_data(
                dynamo_table,
                role.role_id,
                {
                    "RepoScheduled": scheduled_time,
                    "ScheduledPerms": role.repoable_services,
                },
            )

            scheduled_roles.append(role)

    LOGGER.info(
        "Scheduled repo for {} days from now for account {} and these roles:\n\t{}".format(
            config.get("repo_schedule_period_days", 7),
            account_number,
            ", ".join([r.role_name for r in scheduled_roles]),
        )
    )

    repokid.hooks.call_hooks(hooks, "AFTER_SCHEDULE_REPO", {"roles": scheduled_roles})


def show_scheduled_roles(account_number, dynamo_table):
    """
    Show scheduled repos for a given account.  For each scheduled show whether scheduled time is elapsed or not.
    """
    roles = Roles(
        [
            Role(get_role_data(dynamo_table, roleID))
            for roleID in tqdm(role_ids_for_account(dynamo_table, account_number))
        ]
    )

    # filter to show only roles that are scheduled
    roles = roles.filter(active=True)
    roles = [role for role in roles if (role.repo_scheduled)]

    header = ["Role name", "Scheduled", "Scheduled Time Elapsed?"]
    rows = []

    curtime = int(time.time())

    for role in roles:
        rows.append(
            [
                role.role_name,
                dt.fromtimestamp(role.repo_scheduled).strftime("%Y-%m-%d %H:%M"),
                role.repo_scheduled < curtime,
            ]
        )

    print(tabulate(rows, headers=header))


def cancel_scheduled_repo(account_number, dynamo_table, role_name=None, is_all=None):
    """
    Cancel scheduled repo for a role in an account
    """
    if not is_all and not role_name:
        LOGGER.error("Either a specific role to cancel or all must be provided")
        return

    if is_all:
        roles = Roles(
            [
                Role(get_role_data(dynamo_table, roleID))
                for roleID in role_ids_for_account(dynamo_table, account_number)
            ]
        )

        # filter to show only roles that are scheduled
        roles = [role for role in roles if (role.repo_scheduled)]

        for role in roles:
            set_role_data(
                dynamo_table, role.role_id, {"RepoScheduled": 0, "ScheduledPerms": []}
            )

        LOGGER.info(
            "Canceled scheduled repo for roles: {}".format(
                ", ".join([role.role_name for role in roles])
            )
        )
        return

    role_id = find_role_in_cache(dynamo_table, account_number, role_name)
    if not role_id:
        LOGGER.warn(
            "Could not find role with name {} in account {}".format(
                role_name, account_number
            )
        )
        return

    role = Role(get_role_data(dynamo_table, role_id))

    if not role.repo_scheduled:
        LOGGER.warn(
            "Repo was not scheduled for role {} in account {}".format(
                role.role_name, account_number
            )
        )
        return

    set_role_data(
        dynamo_table, role.role_id, {"RepoScheduled": 0, "ScheduledPerms": []}
    )
    LOGGER.info(
        "Successfully cancelled scheduled repo for role {} in account {}".format(
            role.role_name, role.account
        )
    )


def _inline_policies_size_exceeds_maximum(policies):
    """Validate the policies, when converted to JSON without whitespace, remain under the size limit.

    Args:
        policies (list<dict>)
    Returns:
        bool
    """
    exported_no_whitespace = json.dumps(policies, separators=(",", ":"))
    if len(exported_no_whitespace) > MAX_AWS_POLICY_SIZE:
        return True
    return False


def _logprint_deleted_and_repoed_policies(
    deleted_policy_names, repoed_policies, role_name, account_number
):
    """Logs data on policies that would otherwise be modified or deleted if the commit flag were set.

    Args:
        deleted_policy_names (list<string>)
        repoed_policies (list<dict>)
        role_name (string)
        account_number (string)

    Returns:
        None
    """
    for name in deleted_policy_names:
        LOGGER.info(
            "Would delete policy from {} with name {} in account {}".format(
                role_name, name, account_number
            )
        )

    if repoed_policies:
        LOGGER.info(
            "Would replace policies for role {} with: \n{} in account {}".format(
                role_name,
                json.dumps(repoed_policies, indent=2, sort_keys=True),
                account_number,
            )
        )


def _delete_policy(name, role, account_number, conn):
    """Deletes the specified IAM Role inline policy.

    Args:
        name (string)
        role (Role object)
        account_number (string)
        conn (dict)

    Returns:
        error (string) or None
    """
    LOGGER.info(
        "Deleting policy with name {} from {} in account {}".format(
            name, role.role_name, account_number
        )
    )
    try:
        delete_role_policy(RoleName=role.role_name, PolicyName=name, **conn)
    except botocore.exceptions.ClientError as e:
        return "Error deleting policy: {} from role: {} in account {}.  Exception: {}".format(
            name, role.role_name, account_number, e
        )


def _replace_policies(repoed_policies, role, account_number, conn):
    """Overwrite IAM Role inline policies with those supplied.

    Args:
        repoed_policies (dict)
        role (Role object)
        account_number (string)
        conn (dict)

    Returns:
        error (string) or None
    """
    LOGGER.info(
        "Replacing Policies With: \n{} (role: {} account: {})".format(
            json.dumps(repoed_policies, indent=2, sort_keys=True),
            role.role_name,
            account_number,
        )
    )

    for policy_name, policy in repoed_policies.items():
        try:
            put_role_policy(
                RoleName=role.role_name,
                PolicyName=policy_name,
                PolicyDocument=json.dumps(policy, indent=2, sort_keys=True),
                **conn,
            )

        except botocore.exceptions.ClientError as e:
            error = "Exception calling PutRolePolicy on {role}/{policy} in account {account}\n{e}\n".format(
                role=role.role_name,
                policy=policy_name,
                account=account_number,
                e=str(e),
            )
            return error


def remove_permissions_from_roles(
    permissions, role_filename, dynamo_table, config, hooks, commit=False
):
    """Loads roles specified in file and calls _remove_permissions_from_role() for each one.

    Args:
        permissions (list<string>)
        role_filename (string)
        commit (bool)

    Returns:
        None
    """
    roles = list()
    with open(role_filename, "r") as fd:
        roles = json.load(fd)

    for role_arn in tqdm(roles):
        arn = ARN(role_arn)
        if arn.error:
            LOGGER.error("INVALID ARN: {arn}".format(arn=role_arn))
            return

        account_number = arn.account_number
        role_name = arn.name.split("/")[-1]

        role_id = find_role_in_cache(dynamo_table, account_number, role_name)
        role = Role(get_role_data(dynamo_table, role_id))

        _remove_permissions_from_role(
            account_number,
            permissions,
            role,
            role_id,
            dynamo_table,
            config,
            hooks,
            commit=commit,
        )

        repokid.hooks.call_hooks(hooks, "AFTER_REPO", {"role": role})


def _remove_permissions_from_role(
    account_number,
    permissions,
    role,
    role_id,
    dynamo_table,
    config,
    hooks,
    commit=False,
):
    """Remove the list of permissions from the provided role.

    Args:
        account_number (string)
        permissions (list<string>)
        role (Role object)
        role_id (string)
        commit (bool)

    Returns:
        None
    """
    repoed_policies, deleted_policy_names = roledata._get_repoed_policy(
        role.policies[-1]["Policy"], permissions
    )

    if _inline_policies_size_exceeds_maximum(repoed_policies):
        LOGGER.error(
            "Policies would exceed the AWS size limit after repo for role: {} in account {}.  "
            "Please manually minify.".format(role.role_name, account_number)
        )
        return

    if not commit:
        _logprint_deleted_and_repoed_policies(
            deleted_policy_names, repoed_policies, role.role_name, account_number
        )
        return

    conn = config["connection_iam"]
    conn["account_number"] = account_number

    for name in deleted_policy_names:
        error = _delete_policy(name, role, account_number, conn)
        if error:
            LOGGER.error(error)

    if repoed_policies:
        error = _replace_policies(repoed_policies, role, account_number, conn)
        if error:
            LOGGER.error(error)

    current_policies = get_role_inline_policies(role.as_dict(), **conn) or {}
    roledata.add_new_policy_version(dynamo_table, role, current_policies, "Repo")

    set_role_data(
        dynamo_table, role.role_id, {"Repoed": datetime.datetime.utcnow().isoformat()}
    )
    _update_repoed_description(role.role_name, **conn)
    _update_role_data(
        role,
        dynamo_table,
        account_number,
        config,
        conn,
        hooks,
        source="ManualPermissionRepo",
        add_no_repo=False,
    )
    LOGGER.info(
        "Successfully removed {permissions} from role: {role} in account {account_number}".format(
            permissions=permissions, role=role.role_name, account_number=account_number
        )
    )


def repo_role(
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
            )
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

    if _inline_policies_size_exceeds_maximum(repoed_policies):
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
        _logprint_deleted_and_repoed_policies(
            deleted_policy_names, repoed_policies, role_name, account_number
        )
        return

    conn = config["connection_iam"]
    conn["account_number"] = account_number

    for name in deleted_policy_names:
        error = _delete_policy(name, role, account_number, conn)
        if error:
            LOGGER.error(error)
            errors.append(error)

    if repoed_policies:
        error = _replace_policies(repoed_policies, role, account_number, conn)
        if error:
            LOGGER.error(error)
            errors.append(error)

    current_policies = get_role_inline_policies(role.as_dict(), **conn) or {}
    roledata.add_new_policy_version(dynamo_table, role, current_policies, "Repo")

    # regardless of whether we're successful we want to unschedule the repo
    set_role_data(
        dynamo_table, role.role_id, {"RepoScheduled": 0, "ScheduledPerms": []}
    )

    repokid.hooks.call_hooks(hooks, "AFTER_REPO", {"role": role})

    if not errors:
        # repos will stay scheduled until they are successful
        set_role_data(
            dynamo_table,
            role.role_id,
            {"Repoed": datetime.datetime.utcnow().isoformat()},
        )
        _update_repoed_description(role.role_name, **conn)
        _update_role_data(
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


def rollback_role(
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
            LOGGER.error(message)
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
                LOGGER.error(message)
                errors.append(message)

    _update_role_data(
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


def repo_all_roles(
    account_number, dynamo_table, config, hooks, commit=False, scheduled=True
):
    """
    Repo all scheduled or eligible roles in an account.  Collect any errors and display them at the end.

    Args:
        account_number (string)
        dynamo_table
        config
        commit (bool): actually make the changes
        scheduled (bool): if True only repo the scheduled roles, if False repo all the (eligible) roles

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

    for role in roles:
        error = repo_role(
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

    if errors:
        LOGGER.error(
            "Error(s) during repo: \n{} (account: {})".format(errors, account_number)
        )
    else:
        LOGGER.info("Successfully repoed roles in account {}".format(account_number))


def repo_stats(output_file, dynamo_table, account_number=None):
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
        LOGGER.error("Unable to write file {}: {}".format(output_file, e))
    else:
        LOGGER.info("Successfully wrote stats to {}".format(output_file))


def main():
    args = docopt(__doc__, version="Repokid {version}".format(version=__version__))

    if args.get("config"):
        config_filename = args.get("<config_filename>")
        _generate_default_config(filename=config_filename)
        sys.exit(0)

    account_number = args.get("<account_number>")

    if not CONFIG:
        config = _generate_default_config()
    else:
        config = CONFIG

    LOGGER.debug("Repokid cli called with args {}".format(args))

    hooks = _get_hooks(config.get("hooks", ["repokid.hooks.loggers"]))
    dynamo_table = dynamo_get_or_create_table(**config["dynamo_db"])

    if args.get("update_role_cache"):
        return update_role_cache(account_number, dynamo_table, config, hooks)

    if args.get("display_role_cache"):
        inactive = args.get("--inactive")
        return display_roles(account_number, dynamo_table, inactive=inactive)

    if args.get("find_roles_with_permissions"):
        permissions = args.get("<permission>")
        output_file = args.get("--output")
        return find_roles_with_permissions(permissions, dynamo_table, output_file)

    if args.get("remove_permissions_from_roles"):
        permissions = args.get("<permission>")
        role_filename = args.get("--role-file")
        commit = args.get("--commit")
        return remove_permissions_from_roles(
            permissions, role_filename, dynamo_table, config, hooks, commit=commit
        )

    if args.get("display_role"):
        role_name = args.get("<role_name>")
        return display_role(account_number, role_name, dynamo_table, config, hooks)

    if args.get("repo_role"):
        role_name = args.get("<role_name>")
        commit = args.get("--commit")
        return repo_role(
            account_number, role_name, dynamo_table, config, hooks, commit=commit
        )

    if args.get("rollback_role"):
        role_name = args.get("<role_name>")
        commit = args.get("--commit")
        selection = args.get("--selection")
        return rollback_role(
            account_number,
            role_name,
            dynamo_table,
            config,
            hooks,
            selection=selection,
            commit=commit,
        )

    if args.get("repo_all_roles"):
        LOGGER.info("Updating role data")
        update_role_cache(account_number, dynamo_table, config, hooks)
        LOGGER.info("Repoing all roles")
        commit = args.get("--commit")
        return repo_all_roles(
            account_number, dynamo_table, config, hooks, commit=commit, scheduled=False
        )

    if args.get("schedule_repo"):
        LOGGER.info("Updating role data")
        update_role_cache(account_number, dynamo_table, config, hooks)
        return schedule_repo(account_number, dynamo_table, config, hooks)

    if args.get("show_scheduled_roles"):
        LOGGER.info("Showing scheduled roles")
        return show_scheduled_roles(account_number, dynamo_table)

    if args.get("cancel_scheduled_repo"):
        role_name = args.get("--role")
        is_all = args.get("--all")
        if not is_all:
            LOGGER.info(
                "Cancelling scheduled repo for role: {} in account {}".format(
                    role_name, account_number
                )
            )
        else:
            LOGGER.info(
                "Cancelling scheduled repo for all roles in account {}".format(
                    account_number
                )
            )
        return cancel_scheduled_repo(
            account_number, dynamo_table, role_name=role_name, is_all=is_all
        )

    if args.get("repo_scheduled_roles"):
        update_role_cache(account_number, dynamo_table, config, hooks)
        LOGGER.info("Repoing scheduled roles")
        commit = args.get("--commit")
        return repo_all_roles(
            account_number, dynamo_table, config, hooks, commit=commit, scheduled=True
        )

    if args.get("repo_stats"):
        output_file = args.get("<output_filename>")
        account_number = args.get("--account")
        return repo_stats(output_file, dynamo_table, account_number=account_number)


if __name__ == "__main__":
    main()
