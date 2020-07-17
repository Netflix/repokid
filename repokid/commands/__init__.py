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
from repokid import CONFIG
from repokid import get_hooks
from repokid.commands.repo import _repo_all_roles, _repo_role, _repo_stats, _rollback_role
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


hooks = get_hooks(CONFIG.get("hooks", ["repokid.hooks.loggers"]))
dynamo_table = dynamo_get_or_create_table(**CONFIG["dynamo_db"])


def update_role_cache(account_number: str):
    return _update_role_cache(account_number)


def display_role_cache(account_numner: str, inactive: bool = False):
    pass


def find_roles_with_permissions(permissions: str, output_file: str = ""):
    pass


def remove_permissions_from_roles(permissions: str, role_filename: str = "", commit: bool = False):
    pass


def display_role(account_number: str, role_name: str):
    pass


def repo_role(account_number: str, role_name: str, commit: bool = False):
    pass


def rollback_role(account_number: str, role_name: str, selection: int = 0, commit: bool = False):
    pass


def repo_all_roles(account_number: str, commit: bool = False, scheduled: bool = False):
    pass


def show_scheduled_roles(account_number: str):
    pass


def cancel_scheduled_repo(account_number: str, role_name: str = "", is_all: bool = False):
    pass


def repo_scheduled_roles(account_number: str, commit: bool = False):
    pass


def repo_stats(account_number: str, output_filename: str = ""):
    pass
