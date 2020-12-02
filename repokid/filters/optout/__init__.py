import time

from repokid.filters import Filter
from repokid.role import RoleList
from repokid.types import RepokidFilterConfig


class OptOutFilter(Filter):
    def __init__(self, config: RepokidFilterConfig = None) -> None:
        super().__init__(config=config)
        self.current_time_epoch = int(time.time())

    def apply(self, input_list: RoleList) -> RoleList:
        opt_out_roles: RoleList = RoleList([])

        for role in input_list:
            if role.opt_out and role.opt_out["expire"] > self.current_time_epoch:
                opt_out_roles.append(role)
        return opt_out_roles
