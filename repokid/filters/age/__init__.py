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

import datetime
import logging

from repokid.filters import Filter
from repokid.role import RoleList

LOGGER = logging.getLogger("repokid")


class AgeFilter(Filter):
    def apply(self, input_list: RoleList) -> RoleList:
        now = datetime.datetime.now()
        if self.config:
            days_delta = self.config.get("minimum_age", 90)
        else:
            LOGGER.info("Minimum age not set in config, using default 90 days")
            days_delta = 90

        ago = datetime.timedelta(days=days_delta)

        too_young = RoleList([])
        for role in input_list:
            if role.create_date and role.create_date > now - ago:
                LOGGER.info(
                    "Role {name} created too recently to cleanup. ({date})".format(
                        name=role.role_name, date=role.create_date
                    )
                )
                too_young.append(role)
        return too_young
