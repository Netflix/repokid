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

from __future__ import annotations

import copy
import datetime
import logging
import time
from typing import Any
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple
from typing import Union
from typing import overload

from dateutil.parser import parse as ts_parse
from pydantic import BaseModel
from pydantic import Field
from pydantic import PrivateAttr
from pydantic import validator

from repokid import CONFIG
from repokid.datasource.access_advisor import AccessAdvisorDatasource
from repokid.exceptions import DynamoDBError
from repokid.exceptions import IntegrityError
from repokid.exceptions import MissingRepoableServices
from repokid.exceptions import ModelError
from repokid.exceptions import NotFoundError
from repokid.exceptions import RoleNotFoundError
from repokid.types import RepokidConfig
from repokid.types import RepokidHooks
from repokid.utils.dynamo import create_dynamodb_entry
from repokid.utils.dynamo import get_role_by_id
from repokid.utils.dynamo import get_role_by_name
from repokid.utils.dynamo import set_role_data
from repokid.utils.permissions import convert_repoable_perms_to_perms_and_services
from repokid.utils.permissions import find_newly_added_permissions
from repokid.utils.permissions import get_permissions_in_policy
from repokid.utils.permissions import get_repoable_permissions
from repokid.utils.permissions import get_repoed_policy
from repokid.utils.permissions import get_services_and_permissions_from_repoable

logger = logging.getLogger("repokid")


def to_camel(string: str) -> str:
    return "".join(word.capitalize() for word in string.split("_"))


class Role(BaseModel):
    aa_data: Optional[List[Dict[str, Any]]] = Field(alias="AAData")
    account: str = Field(default="")
    active: Optional[bool] = Field()
    arn: str = Field(default="")
    assume_role_policy_document: Dict[str, Any] = Field(default={})
    create_date: Optional[datetime.datetime] = Field()
    disqualified_by: List[str] = Field(default=[])
    last_updated: Optional[datetime.datetime] = Field()
    no_repo_permissions: Dict[str, int] = Field(default={})
    opt_out: Dict[str, Any] = Field(default={})
    policies: List[Dict[str, Any]] = Field(default=[])
    refreshed: Optional[str] = Field()
    repoable_permissions: int = Field(default=0)
    repoable_services: List[str] = Field(default=[])
    repoed: Optional[str] = Field()
    repo_scheduled: int = Field(default=0)
    role_id: str = Field(default="")
    role_name: str = Field(default="")
    scheduled_perms: List[str] = Field(default=[])
    stats: List[Dict[str, Any]] = Field(default=[])
    tags: List[Dict[str, Any]] = Field(default=[])
    total_permissions: Optional[int] = Field()
    config: RepokidConfig = Field(default=CONFIG)
    _dirty: bool = PrivateAttr(default=False)
    _default_exclude: Set[str] = {
        "role_id",
        "account",
        "config",
        "_dirty",
        "_updated_fields",
    }
    # TODO: read exclude_new_permissions_for_days from config
    _no_repo_secs: int = 24 * 60 * 60 * 14
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

    @validator("create_date")
    def datetime_normalize(cls, v: datetime.datetime) -> datetime.datetime:
        return datetime.datetime.fromtimestamp(v.timestamp())

    def add_policy_version(
        self, policy: Dict[str, Any], source: str = "Scan", store: bool = True
    ) -> bool:
        if not policy:
            logger.debug("no policy provided, not adding")
            return False
        if self.policies:
            last_policy = self.policies[-1]["Policy"]
            last_source = self.policies[-1]["Source"]
            if policy == last_policy and source == last_source:
                # we're already up to date, so this is a noop
                return False
        policy_entry = {
            "Source": source,
            "Discovered": datetime.datetime.now().isoformat(),
            "Policy": policy,
        }
        self.policies.append(policy_entry)
        self._calculate_no_repo_permissions()
        if store:
            self.store(fields=["Policies", "NoRepoPermissions"])
        return True

    def calculate_repo_scores(self, minimum_age: int, hooks: RepokidHooks) -> None:
        (
            all_permissions,
            eligible_permissions,
        ) = self.get_permissions_for_policy_version()
        self.total_permissions = len(all_permissions)
        if self.disqualified_by or not self.aa_data:
            self.repoable_permissions = 0
            self.repoable_services = []
            return
        repoable_permissions = get_repoable_permissions(
            self.account,
            self.role_name,
            all_permissions,
            self.aa_data,
            self.no_repo_permissions,
            self.role_id,
            minimum_age,
            hooks,
        )
        (
            repoable_permissions_set,
            repoable_services_set,
        ) = convert_repoable_perms_to_perms_and_services(
            all_permissions, repoable_permissions
        )
        # combine repoable services and permissions, convert to list, then sort
        repoable_services_list = list(
            repoable_services_set.union(repoable_permissions_set)
        )
        self.repoable_services = sorted(repoable_services_list)
        self.repoable_permissions = len(repoable_permissions)

    def get_permissions_for_policy_version(
        self, selection: int = -1, warn_unknown_perms: bool = False
    ) -> Tuple[Set[str], Set[str]]:
        if not self.policies:
            return set(), set()

        return get_permissions_in_policy(
            self.policies[selection]["Policy"], warn_unknown_perms=warn_unknown_perms
        )

    def _calculate_no_repo_permissions(self) -> None:
        if not self.policies:
            return
        try:
            previous_policy = self.policies[-2]
        except IndexError:
            previous_policy = {}
        new_policy = self.policies[-1]
        newly_added_permissions = find_newly_added_permissions(
            previous_policy.get("Policy", {}), new_policy.get("Policy", {})
        )
        current_time = int(time.time())

        # iterate through a copy of self.no_repo_permissions and remove expired items from
        # the source dict
        for permission, expiration in copy.copy(self.no_repo_permissions).items():
            if current_time > expiration:
                self.no_repo_permissions.pop(permission)

        expire_time = current_time + self._no_repo_secs
        for permission in newly_added_permissions:
            self.no_repo_permissions[permission] = expire_time

    def get_repoed_policy(
        self, scheduled: bool = False
    ) -> Tuple[Dict[str, Any], List[str]]:
        if not self.repoable_services:
            raise MissingRepoableServices("role must be updated")
        if scheduled:
            permissions, services = get_services_and_permissions_from_repoable(
                self.scheduled_perms
            )
            repoable = [
                p
                for p in self.repoable_services
                if p in self.scheduled_perms or p.split(":")[0] in services
            ]
        else:
            repoable = self.repoable_services

        repoed_policies, deleted_policy_names = get_repoed_policy(
            self.policies[-1]["Policy"], set(repoable)
        )
        return repoed_policies, deleted_policy_names

    def is_eligible_for_repo(self) -> Tuple[bool, str]:
        if len(self.disqualified_by) > 0:
            return False, f"disqualified by {', '.join(self.disqualified_by)}"
        if not self.aa_data:
            return False, "no Access Advisor data available"
        if not self.repoable_permissions and not self.scheduled_perms:
            return False, "no repoable permissions"
        stale_aa_services = self._stale_aa_services()
        if stale_aa_services:
            return (
                False,
                f"stale Access Advisor data for {', '.join(stale_aa_services)}",
            )
        return True, ""

    def _stale_aa_services(self) -> List[str]:
        thresh = datetime.datetime.now() - datetime.timedelta(
            days=self.config["repo_requirements"]["oldest_aa_data_days"]
        )
        stale_services = []
        if self.aa_data:
            for service in self.aa_data:
                if ts_parse(service["lastUpdated"], ignoretz=True) < thresh:
                    stale_services.append(service["serviceName"])
        return stale_services

    def _update_opt_out(self) -> None:
        if self.opt_out and int(self.opt_out["expire"]) < int(time.time()):
            self.opt_out = {}

    def _update_refreshed(self) -> None:
        self.refreshed = datetime.datetime.now().isoformat()

    def update(self, values: Dict[str, Any], store: bool = True) -> None:
        self._dirty = True
        self._updated_fields.update(values.keys())
        temp_role = Role(**values)
        role_data = temp_role.dict(exclude=self._default_exclude)
        for k, v in role_data.items():
            setattr(self, k, v)
        if store:
            fields = list(values.keys())
            self.store(fields=fields)

    def fetch_aa_data(self) -> None:
        if not self.arn:
            raise ModelError(
                "missing arn on Role instance, cannot retrieve Access Advisor data"
            )

        aardvark_data = AccessAdvisorDatasource()

        try:
            self.aa_data = aardvark_data.get(self.arn)
        except NotFoundError:
            self.aa_data = []

    def fetch(
        self,
        fields: Optional[List[str]] = None,
        update: bool = True,
        fetch_aa_data: bool = False,
    ) -> None:
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
            raise ModelError(
                "missing role_id or role_name and account on Role instance"
            )

        if update:
            self.update(stored_role_data, store=False)
            self._updated_fields - set(stored_role_data.keys())
            if fetch_aa_data:
                self.fetch_aa_data()

    def mark_inactive(self, store: bool = True) -> None:
        self.active = False
        if store:
            self.store(fields=["Active"])

    def store(self, fields: Optional[List[str]] = None) -> None:
        create = False
        try:
            remote_role_data = Role(role_id=self.role_id)
            remote_role_data.fetch(fields=["LastUpdated"])
            if (
                remote_role_data.last_updated
                and self.last_updated
                and remote_role_data.last_updated > self.last_updated
            ):
                raise IntegrityError("stored role has been updated since last fetch")
        except RoleNotFoundError:
            create = True

        self.last_updated = datetime.datetime.now()

        if create:
            # TODO: handle this case in set_role_data() to simplify logic here
            create_dynamodb_entry(
                self.dict(
                    by_alias=True, exclude={"config", "_dirty", "_updated_fields"}
                )
            )
            self._updated_fields = set()
        else:
            if fields:
                include_fields = set(fields)
                include_fields.add("last_updated")
                set_role_data(
                    self.role_id,
                    self.dict(
                        include=include_fields,
                        by_alias=True,
                        exclude=self._default_exclude,
                    ),
                )
                self._updated_fields - set(fields)
            else:
                set_role_data(
                    self.role_id,
                    self.dict(by_alias=True, exclude=self._default_exclude),
                )
                self._updated_fields = set()
        self._dirty = False

    def gather_role_data(
        self,
        current_policy: Dict[str, Any],
        hooks: RepokidHooks,
        config: Optional[RepokidConfig] = None,
        source: str = "Scan",
        add_no_repo: bool = True,
        store: bool = True,
    ) -> None:
        config = config or CONFIG
        try:
            self.fetch()
        except RoleNotFoundError as e:
            # we don't have this role in DynamoDB yet, but that's okay
            logger.debug("%s, will be created", e)
        self.fetch_aa_data()
        policy_added = self.add_policy_version(
            current_policy, source=source, store=False
        )
        if policy_added and add_no_repo:
            self._calculate_no_repo_permissions()
        self._update_opt_out()
        self._update_refreshed()
        minimum_age = config["filter_config"]["AgeFilter"]["minimum_age"]
        self.calculate_repo_scores(minimum_age, hooks)
        self.calculate_stats(source=source, store=False)
        if store:
            self.store()

    def calculate_stats(self, source: str = "Scan", store: bool = True) -> None:
        new_stats = {
            "Date": datetime.datetime.now().isoformat(),
            "DisqualifiedBy": self.disqualified_by,
            "PermissionsCount": self.total_permissions,
            "RepoablePermissionsCount": self.repoable_permissions,
            "Source": source,
        }
        try:
            cur_stats = self.stats[-1]
        except IndexError:
            cur_stats = {
                "DisqualifiedBy": [],
                "PermissionsCount": 0,
                "RepoablePermissionsCount": 0,
            }

        check_fields = [
            "DisqualifiedBy",
            "PermissionsCount",
            "RepoablePermissionsCount",
        ]
        changed = any(
            [new_stats.get(item) != cur_stats.get(item) for item in check_fields]
        )
        if changed:
            self.stats.append(new_stats)
        if store:
            self.store(fields=["stats"])


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

    @classmethod
    def from_ids(
        cls,
        id_list: Iterable[str],
        fetch: bool = True,
        fields: Optional[List[str]] = None,
    ) -> RoleList:
        role_list = cls([Role(role_id=role_id) for role_id in id_list])
        if fetch:
            map(lambda r: r.fetch(fields=fields), role_list)
        return role_list

    def append(self, role: Role) -> None:
        if not isinstance(role, Role):
            raise AttributeError("cannot add non-Role to RoleList")
        self.roles.append(role)

    def role_id_list(self) -> List[str]:
        return [role.role_id for role in self.roles]

    def get_active(self) -> RoleList:
        return self.filter(active=True)

    def get_by_id(self, role_id: str) -> Optional[Role]:
        try:
            return self.filter(role_id=role_id)[0]
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

    def store(self, fields: Optional[List[str]] = None) -> None:
        for role in self.roles:
            logger.info("storing role %s", role.arn)
            try:
                role.store(fields=fields)
            except DynamoDBError as e:
                logger.error("could not store role %s: %s", role.arn, e, exc_info=True)

    def update_stats(self, source: str = "Scan", store: bool = True) -> None:
        for role in self.roles:
            role.calculate_stats(source=source, store=store)

    def fetch_all(self, fetch_aa_data: bool = False) -> None:
        for role in self.roles:
            role.fetch(fetch_aa_data=fetch_aa_data)
