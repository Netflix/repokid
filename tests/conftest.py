#  Copyright 2020 Netflix, Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import pytest

from repokid.role import Role
from tests import vars


@pytest.fixture(scope="function")
def mock_role(role_dict):
    return Role(**role_dict)


@pytest.fixture(scope="session")
def role_dict():
    return {
        "aa_data": vars.aa_data,
        "account": vars.account,
        "active": vars.active,
        "arn": vars.arn,
        "assume_role_policy_document": vars.assume_role_policy_document,
        "create_date": vars.create_date,
        "disqualified_by": vars.disqualified_by,
        "last_updated": vars.last_updated,
        "no_repo_permissions": vars.no_repo_permissions,
        "opt_out": vars.opt_out,
        "policies": vars.policies,
        "refreshed": vars.refreshed,
        "repoable_permissions": vars.repoable_permissions,
        "repoable_services": vars.repoable_services,
        "repoed": vars.repoed,
        "repo_scheduled": vars.repo_scheduled,
        "role_id": vars.role_id,
        "role_name": vars.role_name,
        "scheduled_perms": vars.scheduled_perms,
        "stats": vars.stats,
        "tags": vars.tags,
        "total_permissions": vars.total_permissions,
    }


@pytest.fixture(scope="session")
def role_dict_with_aliases():
    return {
        "AAData": vars.aa_data,
        "Account": vars.account,
        "Active": vars.active,
        "Arn": vars.arn,
        "AssumeRolePolicyDocument": vars.assume_role_policy_document,
        "CreateDate": vars.create_date,
        "DisqualifiedBy": vars.disqualified_by,
        "LastUpdated": vars.last_updated,
        "NoRepoPermissions": vars.no_repo_permissions,
        "OptOut": vars.opt_out,
        "Policies": vars.policies,
        "Refreshed": vars.refreshed,
        "RepoablePermissions": vars.repoable_permissions,
        "RepoableServices": vars.repoable_services,
        "Repoed": vars.repoed,
        "RepoScheduled": vars.repo_scheduled,
        "RoleId": vars.role_id,
        "RoleName": vars.role_name,
        "ScheduledPerms": vars.scheduled_perms,
        "Stats": vars.stats,
        "Tags": vars.tags,
        "TotalPermissions": vars.total_permissions,
    }
