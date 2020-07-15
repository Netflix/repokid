from repokid.filters import Filter


class LambdaFilter(Filter):
    def apply(self, input_list):
        lambda_roles = []

        for role in input_list:
            if "lambda" in str(role.assume_role_policy_document).lower():
                lambda_roles.append(role)
        return list(lambda_roles)
