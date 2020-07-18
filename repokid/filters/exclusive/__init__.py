import fnmatch
import logging

from repokid.filters import Filter

LOGGER = logging.getLogger("repokid")


class ExclusiveFilter(Filter):
    def __init__(self, config=None):
        current_account = config.get("current_account") or None
        if not current_account:
            LOGGER.error("Unable to get current account for Exclusive Filter")

        exclusive_role_globs = set()
        exclusive_role_globs.update(
            [role_glob.lower() for role_glob in config.get(current_account, [])]
        )
        exclusive_role_globs.update(
            [role_glob.lower() for role_glob in config.get("all", [])]
        )

        self.exclusive_role_globs = exclusive_role_globs

    def apply(self, input_list):
        exclusive_roles = []
        filtered_roles = []

        for role_glob in self.exclusive_role_globs:
            exclusive_roles += [
                role
                for role in input_list
                if fnmatch.fnmatch(role.role_name.lower(), role_glob)
            ]
        filtered_roles = list(set(input_list) - set(exclusive_roles))
        return filtered_roles
