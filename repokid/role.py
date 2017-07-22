#     Copyright 2017 Netflix, Inc.
#
#     Licensed under the Apache License, Version 2.0 (the "License");
#     you may not use this file except in compliance with the License.
#     You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS,
#     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#     See the License for the specific language governing permissions and
#     limitations under the License.


class Role(object):
    def __init__(self, role_dict):
        self.aa_data = role_dict.get('AAData', {})
        self.active = role_dict.get('Active', True)
        self.arn = role_dict.get('Arn', None)
        self.assume_role_policy_document = role_dict.get('AssumeRolePolicyDocument', None)
        self.create_date = role_dict.get('CreateDate', None)
        self.disqualified_by = role_dict.get('DisqualifiedBy', [])
        self.no_repo_permissions = role_dict.get('NoRepoPermissions', {})
        self.opt_out = role_dict.get('OptOut', {})
        self.policies = role_dict.get('Policies', [])
        self.refreshed = role_dict.get('Refreshed', '')
        self.repoable_permissions = role_dict.get('RepoablePermissions', 0)
        self.repoable_services = role_dict.get('RepoableServices', [])
        self.repoed = role_dict.get('Repoed', '')
        self.role_id = role_dict.get('RoleId', None)
        self.role_name = role_dict.get('RoleName', None)
        self.stats = role_dict.get('Stats', [])
        self.total_permissions = role_dict.get('TotalPermissions', 0)

        self.account = role_dict.get('Account', None) or self.arn.split(':')[4] if self.arn else None

    def as_dict(self):
        return {'AAData': self.aa_data,
                'Account': self.account,
                'Active': self.active,
                'Arn': self.arn,
                'AssumeRolePolicyDocument': self.assume_role_policy_document,
                'CreateDate': self.create_date,
                'DisqualifiedBy': self.disqualified_by,
                'Policies': self.policies,
                'NoRepoPermissions': self.no_repo_permissions,
                'OptOut': self.opt_out,
                'Refreshed': self.refreshed,
                'RepoablePermissions': self.repoable_permissions,
                'RepoableServices': self.repoable_services,
                'Repoed': self.repoed,
                'RoleId': self.role_id,
                'RoleName': self.role_name,
                'Stats': self.stats,
                'TotalPermissions': self.total_permissions}

    def __eq__(self, other):
        return self.role_id == other

    def __hash__(self):
        return hash(self.role_id)

    def __repr__(self):
        return self.role_id


class Roles(object):
    def __init__(self, role_object_list):
        self.roles = role_object_list

    def __getitem__(self, index):
        return self.roles[index]

    def __len__(self):
        return len(self.roles)

    def __repr__(self):
        return [role.role_id for role in self.roles]

    def __eq__(self, other):
        return (all(role.role_id in other for role in self.roles) and
                all(role.role_id in self.roles for role in other))

    # def append(self, role):
    #     self.roles.append(role)

    def role_id_list(self):
        return [role.role_id for role in self.roles]

    def get_by_id(self, id):
        try:
            return self.filter(role_id=id)[0]
        except IndexError:
            return None

    def filter(self, **kwargs):
        roles = self.roles
        for arg, value in kwargs.items():
            roles = [role for role in roles if getattr(role, arg, None) == value]
        return roles
