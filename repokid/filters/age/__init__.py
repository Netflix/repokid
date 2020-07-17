import datetime
import logging

from dateutil.tz import tzlocal
from repokid.filters import Filter

LOGGER = logging.getLogger("repokid")


class AgeFilter(Filter):
    def apply(self, input_list):
        now = datetime.datetime.now(tzlocal())
        try:
            days_delta = self.config["minimum_age"]
        except KeyError:
            LOGGER.info("Minimum age not set in config, using default 90 days")
            days_delta = 90

        ago = datetime.timedelta(days=days_delta)

        too_young = []
        for role in input_list:
            if role.create_date > now - ago:
                LOGGER.info(
                    "Role {name} created too recently to cleanup. ({date})".format(
                        name=role.role_name, date=role.create_date
                    )
                )
                too_young.append(role)
        return too_young
