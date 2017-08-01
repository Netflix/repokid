from repokid.cli.repokid_cli import Filter
from repokid import LOGGER


class BlacklistFilter(Filter):
    def __init__(self, config=None):
        self.config = config

        current_account = config.get('current_account') or None
        if not current_account:
            LOGGER.error('Unable to get current account for Blacklist Filter')

        overridden_role_names = set()
        overridden_role_names.update([rolename.lower() for rolename in config.get(current_account, [])])
        overridden_role_names.update([rolename.lower() for rolename in config.get('all', [])])
        self.overridden_role_names = overridden_role_names

    def apply(self, input_list):
        blacklisted_roles = []
        for role in input_list:
            if role.role_name.lower() in self.overridden_role_names:
                blacklisted_roles.append(role)
        return blacklisted_roles
