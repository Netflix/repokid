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
from __future__ import annotations

import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class Role(BaseModel):
    aa_data: Optional[List] = Field(alias="AAData")
    account: Optional[str] = Field(alias="Account")
    active: Optional[bool] = Field(alias="Active")
    arn: Optional[str] = Field(alias="Arn")
    assume_role_policy_document: Dict = Field(
        alias="AssumeRolePolicyDocument", default={}
    )
    create_date: Optional[datetime.datetime] = Field(alias="CreateDate")
    disqualified_by: List = Field(alias="DisqualifiedBy", default=[])
    no_repo_permissions: Dict = Field(alias="NoRepoPermissions", default={})
    opt_out: Dict = Field(alias="OptOut", default={})
    policies: List = Field(alias="Policies", default=[])
    refreshed: Optional[str] = Field(alias="Refreshed")
    repoable_permissions: Optional[int] = Field(alias="RepoablePermissions")
    repoable_services: List = Field(alias="RepoableServices", default=[])
    repoed: Optional[str] = Field(alias="Repoed")
    repo_scheduled: Optional[int] = Field(alias="RepoScheduled")
    role_id: Optional[str] = Field(alias="RoleId")
    role_name: Optional[str] = Field(alias="RoleName")
    scheduled_perms: List = Field(alias="ScheduledPerms", default=[])
    stats: List = Field(alias="Stats", default=[])
    tags: List = Field(alias="Tags", default=[])
    total_permissions: Optional[int] = Field(alias="TotalPermissions")

    def __eq__(self, other: str) -> bool:
        return self.role_id == other

    def __hash__(self) -> int:
        return hash(self.role_id)

    def __repr__(self) -> str:
        return self.role_id


class Roles(object):
    def __init__(self, role_object_list: List[Role]):
        self.roles: List[Role] = role_object_list

    def __getitem__(self, index: int) -> Role:
        return self.roles[index]

    def __len__(self) -> int:
        return len(self.roles)

    def __repr__(self) -> str:
        return str([role.role_id for role in self.roles])

    def __eq__(self, other: Roles) -> bool:
        return all(role.role_id in other for role in self.roles) and all(
            role.role_id in self.roles for role in other
        )

    def append(self, role: Role):
        self.roles.append(role)

    def role_id_list(self) -> List[str]:
        return [role.role_id for role in self.roles]

    def get_by_id(self, id) -> Optional[Role]:
        try:
            return self.filter(role_id=id)[0]
        except IndexError:
            return None

    def filter(self, **kwargs) -> List[Role]:
        roles = self.roles
        for arg, value in kwargs.items():
            roles = [role for role in roles if getattr(role, arg, None) == value]
        return roles
