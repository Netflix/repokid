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
from pydantic import PrivateAttr

from repokid import CONFIG
from repokid.exceptions import IntegrityError
from repokid.exceptions import RoleModelError
from repokid.exceptions import RoleNotFoundError
from repokid.types import RepokidConfig
from repokid.utils.aardvark import get_aardvark_data
from repokid.utils.dynamo_v2 import create_dynamodb_entry
from repokid.utils.dynamo_v2 import get_role_by_id
from repokid.utils.dynamo_v2 import get_role_by_name
from repokid.utils.dynamo_v2 import set_role_data


def to_camel(string: str) -> str:
    return "".join(word.capitalize() for word in string.split("_"))


def update(r: Role, updates: Dict[str, Any], store: bool = False) -> Role:
    new_role = r.copy(update=updates)
    if store:
        # TODO: add store logic
        pass

    return new_role


class Role(BaseModel):
    aa_data: Optional[List[Dict[str, Any]]] = Field(alias="AAData")
    account: str = Field(default="")
    active: Optional[bool] = Field()
    arn: str = Field(default="")
    assume_role_policy_document: Dict[str, Any] = Field(default={})
    create_date: Optional[datetime.datetime] = Field()
    disqualified_by: List[str] = Field(default=[])
    last_updated: datetime.datetime = Field(default_factory=datetime.datetime.now)
    no_repo_permissions: Dict[str, Any] = Field(default={})
    opt_out: Dict[str, int] = Field(default={})
    policies: List[Dict[str, Any]] = Field(default=[])
    refreshed: Optional[str] = Field()
    repoable_permissions: int = Field(default=0)
    repoable_services: List[str] = Field(default=[])
    repoed: Optional[str] = Field()
    repo_scheduled: float = Field(default=0.0)
    role_id: str = Field(default="")
    role_name: str = Field(default="")
    scheduled_perms: Set[str] = Field(default=[])
    stats: List[Dict[str, Any]] = Field(default=[])
    tags: List[Dict[str, Any]] = Field(default=[])
    total_permissions: Optional[int] = Field()
    config: RepokidConfig = Field(default=CONFIG)
    _dirty: bool = PrivateAttr(default=False)
    _default_exclude = {
        "role_id",
        "role_name",
        "account",
        "config",
        "_dirty",
        "_updated_fields",
    }
    _updated_fields: Set[str] = PrivateAttr(default_factory=set)

    class Config:
        alias_generator = to_camel
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        underscore_attrs_are_private = True

    def __eq__(self, other: object) -> bool:
        return self.role_id == other

    def __hash__(self) -> int:
        return hash(self.role_id)

    def __repr__(self) -> str:
        return f"<Role {self.role_id}>"

    def update(self, values: Dict[str, Any], store: bool = True) -> None:
        self._dirty = True
        self._updated_fields.update(values.keys())
        temp_role = Role(**values)
        role_data = temp_role.dict(exclude_unset=True, exclude=self._default_exclude)
        for k, v in role_data.items():
            setattr(self, k, v)
        if store:
            self.store()

    def fetch_aa_data(self, config: RepokidConfig = None):
        config = config or CONFIG
        if not self.arn:
            raise RoleModelError(
                "missing arn on Role instance, cannot retrieve Access Advisor data"
            )

        aardvark_data = get_aardvark_data(
            config.get("aardvark_api_location"), arn=self.arn
        )

        self.aa_data = aardvark_data.get(self.arn)

    def fetch(self, fields: Optional[List[str]] = None, update: bool = True):
        if self._dirty:
            raise IntegrityError(
                "role object has unsaved modifications, fetching may overwrite changes"
            )

        if self.role_id:
            stored_role_data = get_role_by_id(self.role_id, fields=fields)
        elif self.role_name and self.account:
            stored_role_data = get_role_by_name(
                self.account, self.role_name, fields=fields
            )
        else:
            raise RoleModelError(
                "missing role_id or role_name and account on Role instance"
            )

        if update:
            temp_role = Role(**stored_role_data)
            role_data = temp_role.dict(exclude_unset=True, exclude=self._default_exclude)
            self.update(role_data, store=False)
            self._updated_fields - set(role_data.keys())

    def store(self, fields: Optional[List[str]] = None):
        try:
            remote_dt = get_role_by_id(
                self.role_id, fields=["LastUpdated"]
            ).get("LastUpdated")
            remote_last_updated = datetime.datetime.strptime(
                remote_dt, "%Y-%m-%d %H:%M"
            )
            if remote_last_updated > self.last_updated:
                raise IntegrityError("stored role has been updated since last fetch")
        except RoleNotFoundError:
            pass

        self.last_updated = datetime.datetime.now()

        try:
            self.fetch(fields=fields, update=False)
        except RoleNotFoundError:
            create_dynamodb_entry(self.dict())
            self._updated_fields = set()

        if fields:
            set_role_data(
                self.role_id,
                self.dict(
                    include=set(fields).add("last_updated"),
                    by_alias=True,
                    exclude=self._default_exclude,
                ),
            )
            self._updated_fields - set(fields)
        else:
            set_role_data(
                self.role_id,
                self.dict(exclude_unset=True, by_alias=True, exclude=self._default_exclude),
            )
            self._updated_fields = set()
        self._dirty = False


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
