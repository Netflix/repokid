import fnmatch
import logging

from repokid.filters import Filter
from repokid.role import RoleList
from repokid.types import RepokidFilterConfig

LOGGER = logging.getLogger("repokid")


class ExclusiveFilter(Filter):
    def __init__(self, config: RepokidFilterConfig = None):
        super().__init__(config=config)
        if not config:
            LOGGER.error(
                "No configuration provided, cannot initialize Exclusive Filter"
            )
            return
        current_account = config.get("current_account", "")
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

    def apply(self, input_list: RoleList) -> RoleList:
        exclusive_roles = []

        for role_glob in self.exclusive_role_globs:
            exclusive_roles += [
                role
                for role in input_list
                if fnmatch.fnmatch(role.role_name.lower(), role_glob)
            ]
        filtered_roles = list(set(input_list) - set(exclusive_roles))
        return RoleList(filtered_roles)
