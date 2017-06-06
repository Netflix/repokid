from repokid.repokid import Filter
from repokid.repokid import LOGGER


class LambdaFilter(Filter):
    def apply(self, input_list):
        lambda_roles = []

        for role in input_list:
            if 'lambda' in str(role['AssumeRolePolicyDocument']).lower():
                lambda_roles.append(role)
        return list(lambda_roles)
