#     Copyright 2020 Netflix, Inc.
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
import copy

dict_to_attr = {
    "AAData": {"attribute": "aa_data", "default": dict()},
    "Account": {"attribute": "account", "default": None},
    "Active": {"attribute": "active", "default": True},
    "Arn": {"attribute": "arn", "default": None},
    "AssumeRolePolicyDocument": {
        "attribute": "assume_role_policy_document",
        "default": None,
    },
    "CreateDate": {"attribute": "create_date", "default": None},
    "DisqualifiedBy": {"attribute": "disqualified_by", "default": list()},
    "NoRepoPermissions": {"attribute": "no_repo_permissions", "default": dict()},
    "OptOut": {"attribute": "opt_out", "default": dict()},
    "Policies": {"attribute": "policies", "default": list()},
    "Refreshed": {"attribute": "refreshed", "default": str()},
    "RepoablePermissions": {"attribute": "repoable_permissions", "default": int()},
    "RepoableServices": {"attribute": "repoable_services", "default": list()},
    "Repoed": {"attribute": "repoed", "default": str()},
    "RepoScheduled": {"attribute": "repo_scheduled", "default": int()},
    "RoleId": {"attribute": "role_id", "default": None},
    "RoleName": {"attribute": "role_name", "default": None},
    "ScheduledPerms": {"attribute": "scheduled_perms", "default": dict()},
    "Stats": {"attribute": "stats", "default": list()},
    "Tags": {"attribute": "tags", "default": list()},
    "TotalPermissions": {"attribute": "total_permissions", "default": int()},
}


class Role(object):
    def __init__(self, role_dict):
        for key, value in list(dict_to_attr.items()):
            setattr(
                self,
                value["attribute"],
                role_dict[key] if key in role_dict else copy.copy(value["default"]),
            )

    def as_dict(self):
        return {
            key: getattr(self, value["attribute"])
            for key, value in dict_to_attr.items()
        }

    def set_attributes(self, attributes_dict):
        for key, value in attributes_dict.items():
            setattr(self, dict_to_attr[key]["attribute"], value)

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
        return str([role.role_id for role in self.roles])

    def __eq__(self, other):
        return all(role.role_id in other for role in self.roles) and all(
            role.role_id in self.roles for role in other
        )

    def append(self, role):
        self.roles.append(role)

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
