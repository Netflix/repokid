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
import time
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Set
from typing import Union
from typing import overload

from pydantic import BaseModel
from pydantic import Field


class Role(BaseModel):
    aa_data: Optional[List[Dict[str, Any]]] = Field(alias="AAData")
    account: str = Field(alias="Account", default="")
    active: Optional[bool] = Field(alias="Active")
    arn: str = Field(alias="Arn", default="")
    assume_role_policy_document: Dict[str, Any] = Field(
        alias="AssumeRolePolicyDocument", default={}
    )
    create_date: Optional[datetime.datetime] = Field(alias="CreateDate")
    disqualified_by: List[str] = Field(alias="DisqualifiedBy", default=[])
    no_repo_permissions: Dict[str, Any] = Field(alias="NoRepoPermissions", default={})
    opt_out: Dict[str, int] = Field(alias="OptOut", default={})
    policies: List[Dict[str, Any]] = Field(alias="Policies", default=[])
    refreshed: Optional[str] = Field(alias="Refreshed")
    repoable_permissions: int = Field(alias="RepoablePermissions", default=0)
    repoable_services: List[str] = Field(alias="RepoableServices", default=[])
    repoed: Optional[str] = Field(alias="Repoed")
    repo_scheduled: float = Field(alias="RepoScheduled", default=0.0)
    role_id: str = Field(alias="RoleId", default="")
    role_name: str = Field(alias="RoleName", default="")
    scheduled_perms: Set[str] = Field(alias="ScheduledPerms", default=[])
    stats: List[Dict[str, Any]] = Field(alias="Stats", default=[])
    tags: List[Dict[str, Any]] = Field(alias="Tags", default=[])
    total_permissions: Optional[int] = Field(alias="TotalPermissions")

    def __eq__(self, other: object) -> bool:
        return self.role_id == other

    def __hash__(self) -> int:
        return hash(self.role_id)

    def __repr__(self) -> str:
        return f"<Role {self.role_id}>"


class RoleList(object):
    def __init__(self, role_object_list: List[Role]):
        self.roles: List[Role] = role_object_list

    @overload
    def __getitem__(self, index: slice) -> RoleList:
        # type info for retrieving a slice of contained roles
        ...

    @overload
    def __getitem__(self, index: int) -> Role:
        # type info for retrieving a single contained role
        ...

    def __getitem__(self, index: Union[int, slice]) -> Union[Role, RoleList]:
        if isinstance(index, slice):
            # return a RoleList if the call was for a slice of contained roles
            return RoleList(self.roles[index])

        return self.roles[index]

    def __len__(self) -> int:
        return len(self.roles)

    def __repr__(self) -> str:
        return str([role.role_id for role in self.roles])

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RoleList):
            return False

        return repr(self) == repr(other)

    def __iter__(self) -> RoleList:
        self._iter_index = 0
        self._len = len(self)
        return self

    def __next__(self) -> Role:
        if self._iter_index < self._len:
            result = self[self._iter_index]
            self._iter_index += 1
            return result
        else:
            raise StopIteration

    def append(self, role: Role) -> None:
        if not isinstance(role, Role):
            raise AttributeError("cannot add non-Role to RoleList")
        self.roles.append(role)

    def role_id_list(self) -> List[str]:
        return [role.role_id for role in self.roles]

    def get_active(self) -> RoleList:
        return self.filter(active=True)

    def get_by_id(self, id: str) -> Optional[Role]:
        try:
            return self.filter(role_id=id)[0]
        except IndexError:
            return None

    def get_scheduled(self) -> RoleList:
        cur_time = int(time.time())
        return RoleList(
            [
                role
                for role in self.roles
                if (role.repo_scheduled and cur_time > role.repo_scheduled)
            ]
        )

    def filter(self, **kwargs: Any) -> RoleList:
        roles = self.roles
        for arg, value in kwargs.items():
            roles = [role for role in roles if getattr(role, arg, None) == value]
        return RoleList(roles)
