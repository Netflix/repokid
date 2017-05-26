import datetime
from dateutil.tz import tzlocal
from repokid.repokid import Filter
from repokid.repokid import LOGGER


class AgeFilter(Filter):
    def apply(self, input_list):
        now = datetime.datetime.now(tzlocal())
        try:
            days_delta = self.config['minimum_age']
        except KeyError:
            LOGGER.info('Minimum age not set in config, using default 90 days')
            days_delta = 90

        ago = datetime.timedelta(days=days_delta)

        too_young = []
        for role in input_list:
            if role['CreateDate'] > now - ago:
                LOGGER.info('Role {name} created too recently to cleanup. ({date})'.format(
                            name=role['RoleName'], date=role['CreateDate']))
                too_young.append(role)
        return too_young
