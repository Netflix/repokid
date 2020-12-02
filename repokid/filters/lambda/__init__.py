from repokid.filters import Filter
from repokid.role import RoleList


class LambdaFilter(Filter):
    def apply(self, input_list: RoleList) -> RoleList:
        lambda_roles: RoleList = RoleList([])

        for role in input_list:
            if "lambda" in str(role.assume_role_policy_document).lower():
                lambda_roles.append(role)
        return lambda_roles
