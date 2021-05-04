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

log = logging.getLogger("repokid")


class AgeFilter(Filter):
    def apply(self, input_list: RoleList) -> RoleList:
        now = datetime.datetime.now()
        if self.config:
            days_delta = self.config.get("minimum_age", 90)
        else:
            log.info("Minimum age not set in config, using default 90 days")
            days_delta = 90

        ago = datetime.timedelta(days=days_delta)

        too_young = RoleList([])
        for role in input_list:
            if not role.create_date:
                log.warning(f"Role {role.role_name} is missing create_date")
                too_young.append(role)
                continue

            # Ensure create_date is an offset-naive datetime
            create_date = datetime.datetime.fromtimestamp(role.create_date.timestamp())

            if create_date > now - ago:
                log.info(
                    f"Role {role.role_name} created too recently to cleanup. ({create_date})"
                )
                too_young.append(role)
        return too_young
