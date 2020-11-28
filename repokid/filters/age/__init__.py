import datetime
import logging

from dateutil.tz import tzlocal

from repokid.filters import Filter
from repokid.role import RoleList

LOGGER = logging.getLogger("repokid")


class AgeFilter(Filter):
    def apply(self, input_list: RoleList) -> RoleList:
        now = datetime.datetime.now(tzlocal())
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
