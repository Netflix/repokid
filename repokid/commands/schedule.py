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
import logging
import time
from datetime import datetime as dt

from tabulate import tabulate

import repokid.hooks
from repokid.role import Role
from repokid.role import RoleList
from repokid.types import RepokidConfig
from repokid.types import RepokidHooks
from repokid.utils.dynamo import find_role_in_cache
from repokid.utils.dynamo import get_all_role_ids_for_account

LOGGER = logging.getLogger("repokid")


def _schedule_repo(
    account_number: str,
    config: RepokidConfig,
    hooks: RepokidHooks,
) -> None:
    """
    Schedule a repo for a given account.  Schedule repo for a time in the future (default 7 days) for any roles in
    the account with repoable permissions.
    """
    scheduled_roles = []
    role_ids = get_all_role_ids_for_account(account_number)
    roles = RoleList.from_ids(role_ids)
    roles.fetch_all(fetch_aa_data=True)

    scheduled_time = int(time.time()) + (
        86400 * config.get("repo_schedule_period_days", 7)
    )
    for role in roles:
        if not role.aa_data:
            LOGGER.warning("Not scheduling %s; missing Access Advisor data", role.arn)
            continue
        if not role.repoable_permissions > 0:
            LOGGER.debug("Not scheduling %s; no repoable permissions", role.arn)
            continue
        if role.repo_scheduled:
            LOGGER.debug(
                "Not scheduling %s; already scheduled for %s",
                role.arn,
                role.repo_scheduled,
            )
            continue

        role.repo_scheduled = scheduled_time
        # freeze the scheduled perms to whatever is repoable right now
        role.repo_scheduled = scheduled_time
        role.scheduled_perms = role.repoable_services
        role.store(["repo_scheduled", "scheduled_perms"])

        scheduled_roles.append(role)

    LOGGER.info(
        "Scheduled repo for {} days from now for account {} and these roles:\n\t{}".format(
            config.get("repo_schedule_period_days", 7),
            account_number,
            ", ".join([r.role_name for r in scheduled_roles]),
        )
    )

    repokid.hooks.call_hooks(hooks, "AFTER_SCHEDULE_REPO", {"roles": scheduled_roles})


def _show_scheduled_roles(account_number: str) -> None:
    """
    Show scheduled repos for a given account.  For each scheduled show whether scheduled time is elapsed or not.
    """
    role_ids = get_all_role_ids_for_account(account_number)
    roles = RoleList.from_ids(role_ids)

    # filter to show only roles that are scheduled
    roles = roles.get_active().get_scheduled()

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


def _cancel_scheduled_repo(
    account_number: str, role_name: str = "", is_all: bool = False
) -> None:
    """
    Cancel scheduled repo for a role in an account
    """
    if not is_all and not role_name:
        LOGGER.error("Either a specific role to cancel or all must be provided")
        return

    if is_all:
        role_ids = get_all_role_ids_for_account(account_number)
        roles = RoleList.from_ids(role_ids)

        # filter to show only roles that are scheduled
        roles = roles.get_scheduled()

        for role in roles:
            role.repo_scheduled = 0
            role.scheduled_perms = []
            role.store(["repo_scheduled", "scheduled_perms"])

        LOGGER.info(
            "Canceled scheduled repo for roles: {}".format(
                ", ".join([role.role_name for role in roles])
            )
        )
        return

    role_id = find_role_in_cache(role_name, account_number)
    if not role_id:
        LOGGER.warn(
            "Could not find role with name {} in account {}".format(
                role_name, account_number
            )
        )
        return

    role = Role(role_id=role_id)
    role.fetch()

    if not role.repo_scheduled:
        LOGGER.warning(
            "Repo was not scheduled for role {} in account {}".format(
                role.role_name, account_number
            )
        )
        return

    role.repo_scheduled = 0
    role.scheduled_perms = []
    role.store(["repo_scheduled", "scheduled_perms"])
    LOGGER.info(
        "Successfully cancelled scheduled repo for role {} in account {}".format(
            role.role_name, role.account
        )
    )
