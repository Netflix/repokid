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

import json
import logging
import sys

from docopt import docopt
from repokid import __version__ as __version__
from repokid import CONFIG
from repokid import get_hooks
from repokid.commands.repo import (
    _repo_all_roles,
    _repo_role,
    _repo_stats,
    _rollback_role,
)
from repokid.commands.role import (
    _display_role,
    _display_roles,
    _find_roles_with_permissions,
    _remove_permissions_from_roles,
)
from repokid.commands.role_cache import _update_role_cache
from repokid.commands.schedule import (
    _cancel_scheduled_repo,
    _schedule_repo,
    _show_scheduled_roles,
)
from repokid.utils.dynamo import dynamo_get_or_create_table


# http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-limits.html

LOGGER = logging.getLogger("repokid")


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

    hooks = get_hooks(config.get("hooks", ["repokid.hooks.loggers"]))
    dynamo_table = dynamo_get_or_create_table(**config["dynamo_db"])

    if args.get("update_role_cache"):
        return _update_role_cache(account_number, dynamo_table, config, hooks)

    if args.get("display_role_cache"):
        inactive = args.get("--inactive")
        return _display_roles(account_number, dynamo_table, inactive=inactive)

    if args.get("find_roles_with_permissions"):
        permissions = args.get("<permission>")
        output_file = args.get("--output")
        return _find_roles_with_permissions(permissions, dynamo_table, output_file)

    if args.get("remove_permissions_from_roles"):
        permissions = args.get("<permission>")
        role_filename = args.get("--role-file")
        commit = args.get("--commit")
        return _remove_permissions_from_roles(
            permissions, role_filename, dynamo_table, config, hooks, commit=commit
        )

    if args.get("display_role"):
        role_name = args.get("<role_name>")
        return _display_role(account_number, role_name, dynamo_table, config, hooks)

    if args.get("repo_role"):
        role_name = args.get("<role_name>")
        commit = args.get("--commit")
        return _repo_role(
            account_number, role_name, dynamo_table, config, hooks, commit=commit
        )

    if args.get("rollback_role"):
        role_name = args.get("<role_name>")
        commit = args.get("--commit")
        selection = args.get("--selection")
        return _rollback_role(
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
        _update_role_cache(account_number, dynamo_table, config, hooks)
        LOGGER.info("Repoing all roles")
        commit = args.get("--commit")
        return _repo_all_roles(
            account_number, dynamo_table, config, hooks, commit=commit, scheduled=False
        )

    if args.get("schedule_repo"):
        LOGGER.info("Updating role data")
        _update_role_cache(account_number, dynamo_table, config, hooks)
        return _schedule_repo(account_number, dynamo_table, config, hooks)

    if args.get("show_scheduled_roles"):
        LOGGER.info("Showing scheduled roles")
        return _show_scheduled_roles(account_number, dynamo_table)

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
        return _cancel_scheduled_repo(
            account_number, dynamo_table, role_name=role_name, is_all=is_all
        )

    if args.get("repo_scheduled_roles"):
        _update_role_cache(account_number, dynamo_table, config, hooks)
        LOGGER.info("Repoing scheduled roles")
        commit = args.get("--commit")
        return _repo_all_roles(
            account_number, dynamo_table, config, hooks, commit=commit, scheduled=True
        )

    if args.get("repo_stats"):
        output_file = args.get("<output_filename>")
        account_number = args.get("--account")
        return _repo_stats(output_file, dynamo_table, account_number=account_number)


if __name__ == "__main__":
    main()
