#  Copyright 2021 Netflix, Inc.
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
import datetime

from dateutil import tz

from repokid.filters.age import AgeFilter
from repokid.role import Role
from repokid.role import RoleList


def test_age_with_tz(mock_role: Role):
    age_filter = AgeFilter()
    create_date = datetime.datetime.now(tz=tz.tzutc()) - datetime.timedelta(days=100)
    assert create_date.tzinfo
    mock_role.create_date = create_date
    role_list = RoleList([mock_role])
    result = age_filter.apply(role_list)
    assert len(result) == 0


def test_age_no_tz(mock_role: Role):
    age_filter = AgeFilter()
    create_date = datetime.datetime.now() - datetime.timedelta(days=100)
    assert not create_date.tzinfo
    mock_role.create_date = create_date
    role_list = RoleList([mock_role])
    result = age_filter.apply(role_list)
    assert len(result) == 0


def test_age_too_young_with_tz(mock_role: Role):
    age_filter = AgeFilter()
    create_date = datetime.datetime.now(tz=tz.tzutc())
    assert create_date.tzinfo
    mock_role.create_date = create_date
    role_list = RoleList([mock_role])
    result = age_filter.apply(role_list)
    assert len(result) == 1


def test_age_too_young_no_tz(mock_role: Role):
    age_filter = AgeFilter()
    create_date = datetime.datetime.now()
    assert not create_date.tzinfo
    mock_role.create_date = create_date
    role_list = RoleList([mock_role])
    result = age_filter.apply(role_list)
    assert len(result) == 1
