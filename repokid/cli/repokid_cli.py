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

import json
import logging
from typing import List
from typing import Optional

from click import Command
from click import Context
from click import Group
from click import argument
from click import group
from click import option
from click import pass_context

from repokid import CONFIG
from repokid import get_hooks
from repokid.commands.repo import _repo_all_roles
from repokid.commands.repo import _repo_role
from repokid.commands.repo import _repo_stats
from repokid.commands.repo import _rollback_role
from repokid.commands.role import _display_role
from repokid.commands.role import _display_roles
from repokid.commands.role import _find_roles_with_permissions
from repokid.commands.role import _remove_permissions_from_roles
from repokid.commands.role_cache import _update_role_cache
from repokid.commands.schedule import _cancel_scheduled_repo
from repokid.commands.schedule import _schedule_repo
from repokid.commands.schedule import _show_scheduled_roles
from repokid.types import RepokidConfig

logger = logging.getLogger("repokid")


def _generate_default_config(filename: str = "") -> RepokidConfig:
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
            "endpoint": "<DYNAMO_TABLE_ENDPOINT (http://localhost:8000 if using docker compose)>",
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
                "json": {"class": "json_log_formatter.JSONFormatter"},
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
            print(f"Unable to open {filename} for writing: {e}")
        else:
            print(f"Successfully wrote sample config to {filename}")
    return config_dict


class AliasedGroup(Group):
    """AliasedGroup provides backward compatibility with the previous Repokid CLI commands"""

    def get_command(self, ctx: Context, cmd_name: str) -> Optional[Command]:
        rv = Group.get_command(self, ctx, cmd_name)
        if rv:
            return rv
        dashed = cmd_name.replace("_", "-")
        for cmd in self.list_commands(ctx):
            if cmd == dashed:
                return Group.get_command(self, ctx, cmd)
        return None


@group(cls=AliasedGroup)
@pass_context
def cli(ctx: Context) -> None:
    ctx.ensure_object(dict)

    if not CONFIG:
        config = _generate_default_config()
    else:
        config = CONFIG

    ctx.obj["config"] = config
    ctx.obj["hooks"] = get_hooks(config.get("hooks", ["repokid.hooks.loggers"]))


@cli.command()
@argument("filename")
@pass_context
def config(ctx: Context, filename: str) -> None:
    _generate_default_config(filename=filename)


@cli.command()
@argument("account_number")
@pass_context
def update_role_cache(ctx: Context, account_number: str) -> None:
    config = ctx.obj["config"]
    hooks = ctx.obj["hooks"]
    _update_role_cache(account_number, config, hooks)


@cli.command()
@argument("account_number")
@option("--inactive", is_flag=True, default=False, help="Include inactive roles")
@pass_context
def display_role_cache(ctx: Context, account_number: str, inactive: bool) -> None:
    _display_roles(account_number, inactive=inactive)


@cli.command()
@argument("permissions", nargs=-1)
@option("--output", "-o", required=False, help="File to write results to")
@pass_context
def find_roles_with_permissions(
    ctx: Context, permissions: List[str], output: str
) -> None:
    _find_roles_with_permissions(permissions, output)


@cli.command()
@argument("permissions", nargs=-1)
@option("--role-file", "-f", required=True, help="File to read roles from")
@option("--commit", "-c", is_flag=True, default=False, help="Commit changes")
@pass_context
def remove_permissions_from_roles(
    ctx: Context, permissions: List[str], role_file: str, commit: bool
) -> None:
    config = ctx.obj["config"]
    hooks = ctx.obj["hooks"]
    _remove_permissions_from_roles(permissions, role_file, config, hooks, commit=commit)


@cli.command()
@argument("account_number")
@argument("role_name")
@pass_context
def display_role(ctx: Context, account_number: str, role_name: str) -> None:
    config = ctx.obj["config"]
    _display_role(account_number, role_name, config)


@cli.command()
@argument("account_number")
@argument("role_name")
@option("--commit", "-c", is_flag=True, default=False, help="Commit changes")
@pass_context
def repo_role(ctx: Context, account_number: str, role_name: str, commit: bool) -> None:
    config = ctx.obj["config"]
    hooks = ctx.obj["hooks"]
    _repo_role(account_number, role_name, config, hooks, commit=commit)


@cli.command()
@argument("account_number")
@argument("role_name")
@option("--selection", "-s", required=True, type=int)
@option("--commit", "-c", is_flag=True, default=False, help="Commit changes")
@pass_context
def rollback_role(
    ctx: Context,
    account_number: str,
    role_name: str,
    selection: int,
    commit: bool,
) -> None:
    config = ctx.obj["config"]
    hooks = ctx.obj["hooks"]
    _rollback_role(
        account_number, role_name, config, hooks, selection=selection, commit=commit
    )


@cli.command()
@argument("account_number")
@option("--commit", "-c", is_flag=True, default=False, help="Commit changes")
@pass_context
def repo_all_roles(ctx: Context, account_number: str, commit: bool) -> None:
    config = ctx.obj["config"]
    hooks = ctx.obj["hooks"]
    logger.info("Updating role data")
    _update_role_cache(account_number, config, hooks)
    _repo_all_roles(account_number, config, hooks, commit=commit, scheduled=False)


@cli.command()
@argument("account_number")
@pass_context
def schedule_repo(ctx: Context, account_number: str) -> None:
    config = ctx.obj["config"]
    hooks = ctx.obj["hooks"]
    logger.info("Updating role data")
    _update_role_cache(account_number, config, hooks)
    _schedule_repo(account_number, config, hooks)


@cli.command()
@argument("account_number")
@pass_context
def show_scheduled_roles(ctx: Context, account_number: str) -> None:
    _show_scheduled_roles(account_number)


@cli.command()
@argument("account_number")
@option("--role", "-r", required=False, type=str)
@option("--all", "-a", is_flag=True, default=False, help="cancel for all roles")
@pass_context
def cancel_scheduled_repo(
    ctx: Context, account_number: str, role: str, all: bool
) -> None:
    _cancel_scheduled_repo(account_number, role_name=role, is_all=all)


@cli.command()
@argument("account_number")
@option("--commit", "-c", is_flag=True, default=False, help="Commit changes")
@pass_context
def repo_scheduled_roles(ctx: Context, account_number: str, commit: bool) -> None:
    config = ctx.obj["config"]
    hooks = ctx.obj["hooks"]
    _update_role_cache(account_number, config, hooks)
    _repo_all_roles(account_number, config, hooks, commit=commit, scheduled=True)


@cli.command()
@argument("account_number")
@option("--output", "-o", required=True, help="File to write results to")
@pass_context
def repo_stats(ctx: Context, account_number: str, output: str) -> None:
    _repo_stats(output, account_number=account_number)


if __name__ == "__main__":
    cli()
