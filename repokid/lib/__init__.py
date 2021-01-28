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
This module contains wrapper functions for the functions contained in the child
modules so developers don't have to worry about passing configs, hooks, and dynamo
clients.
"""
from typing import List

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

hooks = get_hooks(CONFIG.get("hooks", ["repokid.hooks.loggers"]))


def update_role_cache(account_number: str) -> None:
    """
    Library wrapper to update data about all roles in a given account.

    Ref: :func:`~repokid.commands.role_cache._update_role_cache`

    Args:
        account_number (string): The current account number Repokid is being run against

    Returns:
        None
    """
    return _update_role_cache(account_number, CONFIG, hooks)


def display_role_cache(account_number: str, inactive: bool = False) -> None:
    """
    Library wrapper to display a table with data about all roles in an account and write a csv file with the data.

    Ref: :func:`~repokid.commands.role_cache._display_roles`

    Args:
        account_number (string): The current account number Repokid is being run against
        inactive (bool): show roles that have historically (but not currently) existed in the account if True

    Returns:
        None
    """
    return _display_roles(account_number, inactive=inactive)


def find_roles_with_permissions(permissions: List[str], output_file: str = "") -> None:
    """
    Library wrapper to search roles in all accounts for a policy with any of the provided permissions, log the ARN of
    each role.

    Ref: :func:`~repokid.commands.role._find_roles_with_permissions`

    Args:
        permissions (list[string]): The name of the permissions to find
        output_file (string): filename to write the output

    Returns:
        None
    """
    return _find_roles_with_permissions(permissions, output_file)


def remove_permissions_from_roles(
    permissions: List[str], role_filename: str, commit: bool = False
) -> None:
    """
    Library wrapper to loads role specified in file and call _remove_permissions_from_role() for each one.

    Ref: :func:`~repokid.commands.role._remove_permissions_from_roles`

    Args:
        permissions (list<string>)
        role_filename (string)
        commit (bool)

    Returns:
        None
    """
    return _remove_permissions_from_roles(
        permissions, role_filename, CONFIG, hooks, commit=commit
    )


def display_role(account_number: str, role_name: str) -> None:
    """
    Library wrapper to display data about a role in a given account

    Ref: :func:`~repokid.commands.role._display_role`

    Args:
        account_number (string): The current account number Repokid is being run against
        role_name (string)

    Returns:
        None
    """
    return _display_role(account_number, role_name, CONFIG)


def repo_role(
    account_number: str, role_name: str, commit: bool = False, update: bool = True
) -> List[str]:
    """
    Library wrapper to calculate what repoing can be done for a role and then actually do it if commit is set.

    Ref: :func:`~repokid.commands.repo._repo_role`

    Args:
        account_number (string): The current account number Repokid is being run against
        role_name (string)
        commit (bool)
        update (bool)

    Returns:
        errors (list): if any
    """
    return _repo_role(account_number, role_name, CONFIG, hooks, commit=commit)


def rollback_role(
    account_number: str, role_name: str, selection: int = 0, commit: bool = False
) -> List[str]:
    """
    Library wrapper to display the historical policy versions for a roll as a numbered list.  Restore to a specific
    version if selected. Indicate changes that will be made and then actually make them if commit is selected.

    Ref: :func:`~repokid.commands.repo._rollback_role`

    Args:
        account_number (string): The current account number Repokid is being run against
        role_name (string)
        selection (int): which policy version in the list to rollback to
        commit (bool): actually make the change

    Returns:
        errors (list): if any
    """
    return _rollback_role(
        account_number, role_name, CONFIG, hooks, selection=selection, commit=commit
    )


def schedule_repo(account_number: str) -> None:
    """
    Library wrapper to schedule a repo for a given account.  Schedule repo for a time in the future (default 7 days) for
    any roles in the account with repoable permissions.

    Ref: :func:`~repokid.commands.repo._repo_all_roles`

    Args:
        account_number (string): The current account number Repokid is being run against

    Returns:
        None
    """
    _update_role_cache(account_number, CONFIG, hooks)
    return _schedule_repo(account_number, CONFIG, hooks)


def repo_all_roles(
    account_number: str, commit: bool = False, update: bool = True, limit: int = -1
) -> None:
    """
    Convenience wrapper for repo_roles() with scheduled=False.

    Ref: :func:`~repokid.commands.repo_roles`

    Args:
        account_number (string): The current account number Repokid is being run against
        commit (bool): actually make the changes
        update (bool): if True run update_role_cache before repoing
        limit (int): limit number of roles to be repoed per run (< 0 is unlimited)

    Returns:
        None
    """
    return repo_roles(
        account_number, commit=commit, scheduled=False, update=update, limit=limit
    )


def repo_scheduled_roles(
    account_number: str, commit: bool = False, update: bool = True, limit: int = -1
) -> None:
    """
    Convenience wrapper for repo_roles() with scheduled=True.

    Ref: :func:`~repokid.commands.repo_roles`

    Args:
        account_number (string): The current account number Repokid is being run against
        commit (bool): actually make the changes
        update (bool): if True run update_role_cache before repoing
        limit (int): limit number of roles to be repoed per run (< 0 is unlimited)

    Returns:
        None
    """
    return repo_roles(
        account_number, commit=commit, scheduled=True, update=update, limit=limit
    )


def repo_roles(
    account_number: str,
    commit: bool = False,
    scheduled: bool = False,
    update: bool = True,
    limit: int = -1,
) -> None:
    """
    Library wrapper to repo all scheduled or eligible roles in an account. Collect any errors and display them at the
    end.

    Ref: :func:`~repokid.commands.repo._repo_all_roles`

    Args:
        account_number (string): The current account number Repokid is being run against
        commit (bool): actually make the changes
        scheduled (bool): if True only repo the scheduled roles, if False repo all the (eligible) roles
        update (bool): if True run update_role_cache before repoing
        limit (int): limit number of roles to be repoed per run (< 0 is unlimited)

    Returns:
        None
    """
    if update:
        _update_role_cache(account_number, CONFIG, hooks)
    return _repo_all_roles(
        account_number, CONFIG, hooks, commit=commit, scheduled=scheduled, limit=limit
    )


def show_scheduled_roles(account_number: str) -> None:
    """
    Library wrapper to show scheduled repos for a given account.  For each scheduled show whether scheduled time is
    elapsed or not.

    Ref: :func:`~repokid.commands.schedule._show_scheduled_roles`

    Args:
        account_number (string): The current account number Repokid is being run against

    Returns:
        None
    """
    return _show_scheduled_roles(account_number)


def cancel_scheduled_repo(
    account_number: str, role_name: str = "", is_all: bool = False
) -> None:
    """
    Library wrapper to cancel scheduled repo for a role in an account.

    Ref: :func:`~repokid.commands.schedule._cancel_scheduled_repo`

    Args:
        account_number (string): The current account number Repokid is being run against
        role_name (string): Role name to cancel scheduled repo for
        is_all (bool): Cancel schedule repos on all roles if True

    Returns:
        None
    """
    return _cancel_scheduled_repo(account_number, role_name=role_name, is_all=is_all)


def repo_stats(output_filename: str = "", account_number: str = "") -> None:
    """
    Library wrapper to create a csv file with stats about roles, total permissions, and applicable filters over time.

    Ref: :func:`~repokid.commands.repo._repo_stats`

    Args:
        output_filename (string): the name of the csv file to write
        account_number (string): if specified only display roles from selected account, otherwise display all

    Returns:
        None
    """
    return _repo_stats(output_filename, account_number=account_number)
