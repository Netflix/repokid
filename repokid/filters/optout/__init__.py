import time

from repokid.filters import Filter


class OptOutFilter(Filter):
    def __init__(self, config=None):
        self.current_time_epoch = int(time.time())

    def apply(self, input_list):
        opt_out_roles = []

        for role in input_list:
            if role.opt_out and role.opt_out["expire"] > self.current_time_epoch:
                opt_out_roles.append(role)
        return list(opt_out_roles)
