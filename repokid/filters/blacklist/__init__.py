from repokid.repokid import Filter
from repokid.repokid import CUR_ACCOUNT_NUMBER


class BlacklistFilter(Filter):
    def __init__(self, config=None):
        self.config = config

        overridden_role_names = set()
        overridden_role_names.update([rolename.lower() for rolename in config.get(CUR_ACCOUNT_NUMBER, [])])
        overridden_role_names.update([rolename.lower() for rolename in config.get('all', [])])
        self.overridden_role_names = overridden_role_names

    def apply(self, input_list):
        blacklisted_roles = []
        for role in input_list:
            if role['RoleName'].lower() in self.overridden_role_names:
                blacklisted_roles.append(role)
        return blacklisted_roles
