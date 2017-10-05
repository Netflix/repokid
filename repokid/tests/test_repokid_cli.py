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
import datetime
import logging
import time
from mock import call, patch

from dateutil.tz import tzlocal

import repokid.cli.repokid_cli
from repokid.role import Role, Roles
import repokid.utils.roledata


AARDVARK_DATA = {
    "arn:aws:iam::123456789012:role/all_services_used": [
        {"lastAuthenticated": int(time.time()) * 1000,
         "serviceNamespace": "iam"},
        {"lastAuthenticated": int(time.time()) * 1000,
         "serviceNamespace": "s3"}],

    "arn:aws:iam::123456789012:role/unused_ec2": [
        {"lastAuthenticated": int(time.time()) * 1000,
         "serviceNamespace": "iam"},
        {"lastAuthenticated": 0,
         "serviceNamespace": "ec2"}],

    "arn:aws:iam::123456789012:role/young_role": [
        {"lastAuthenticated": int(time.time()) * 1000,
         "serviceNamespace": "iam"},
        {"lastAuthenticated": int(time.time()) * 1000,
         "serviceNamespace": "s3"}]
}

ROLE_POLICIES = {
    'all_services_used': {
            'iam_perms': {
                'Version': '2012-10-17',
                'Statement': [
                    {'Action': ['iam:AddRoleToInstanceProfile', 'iam:AttachRolePolicy'],
                     'Resource': ['*'],
                     'Effect': 'Allow'}]},

            's3_perms': {
                'Version': '2012-10-17',
                'Statement': [
                    {'Action': ['s3:CreateBucket', 's3:DeleteBucket'],
                     'Resource': ['*'],
                     'Effect': 'Allow'}]}},
    'unused_ec2': {
            'iam_perms': {
                'Version': '2012-10-17',
                'Statement': [
                    {'Action': ['iam:AddRoleToInstanceProfile', 'iam:AttachRolePolicy'],
                     'Resource': ['*'],
                     'Effect': 'Allow'}]},

            'ec2_perms': {
                'Version': '2012-10-17',
                'Statement': [
                    {'Action': ['ec2:AllocateHosts', 'ec2:AssociateAddress'],
                     'Resource': ['*'],
                     'Effect': 'Allow'}]}}
}

ROLES = [
    {
        "Arn": "arn:aws:iam::123456789012:role/all_services_used",
        "CreateDate": datetime.datetime(2017, 1, 31, 12, 0, 0, tzinfo=tzlocal()),
        "RoleId": "AROAABCDEFGHIJKLMNOPA",
        "RoleName": "all_services_used",
        "Active": True
    },
    {
        "Arn": "arn:aws:iam::123456789012:role/unused_ec2",
        "CreateDate": datetime.datetime(2017, 1, 31, 12, 0, 0, tzinfo=tzlocal()),
        "RoleId": "AROAABCDEFGHIJKLMNOPB",
        "RoleName": "unused_ec2",
        "Active": True,
    },
    {
        "Arn": "arn:aws:iam::123456789012:role/young_role",
        "CreateDate": datetime.datetime.now(tzlocal()) - datetime.timedelta(5),
        "RoleId": "AROAABCDEFGHIJKLMNOPC",
        "RoleName": "young_role",
        "Active": True,
    },
    {
        "Arn": "arn:aws:iam::123456789012:role/inactive_role",
        "CreateDate": datetime.datetime.now(tzlocal()) - datetime.timedelta(5),
        "RoleId": "AROAABCDEFGHIJKLMNOPD",
        "RoleName": "inactive_role",
        "Active": False,
    }
]

ROLES_FOR_DISPLAY = [
    {
        "TotalPermissions": 4,
        "RepoablePermissions": 0,
        "Repoed": "Never",
        "RepoableServices": [],
        "Refreshed": "Someday"
    },
    {
        "TotalPermissions": 4,
        "RepoablePermissions": 2,
        "Repoed": "Never",
        "RepoableServices": ["ec2"],
        "Refreshed": "Someday"
    },
    {
        "TotalPermissions": 4,
        "RepoablePermissions": 0,
        "Repoed": "Never",
        "RepoableServices": [],
        "Refreshed": "Someday"
    },
    {
        "TotalPermissions": 4,
        "RepoablePermissions": 0,
        "Repoed": "Never",
        "RepoableServices": [],
        "Refreshed": "Someday"
    }
]


class TestRepokidCLI(object):
    @patch('repokid.utils.roledata.update_stats')
    @patch('repokid.utils.roledata.find_and_mark_inactive')
    @patch('repokid.utils.roledata.update_role_data')
    @patch('repokid.utils.roledata._calculate_repo_scores')
    @patch('repokid.cli.repokid_cli.set_role_data')
    @patch('repokid.cli.repokid_cli._get_aardvark_data')
    @patch('repokid.cli.repokid_cli.get_role_inline_policies')
    @patch('repokid.cli.repokid_cli.list_roles')
    def test_repokid_update_role_cache(self, mock_list_roles, mock_get_role_inline_policies,
                                       mock_get_aardvark_data, mock_set_role_data, mock_calculate_repo_scores,
                                       mock_update_role_data, mock_find_and_mark_inactive, mock_update_stats):

        hooks = {}
        # only active roles
        mock_list_roles.return_value = ROLES[:3]

        mock_get_role_inline_policies.side_effect = [ROLE_POLICIES['all_services_used'],
                                                     ROLE_POLICIES['unused_ec2'],
                                                     ROLE_POLICIES['all_services_used']]

        mock_get_aardvark_data.return_value = AARDVARK_DATA

        def update_role_data(dynamo_table, account_number, role, current_policies):
            role.policies = role.policies = [{'Policy': current_policies}]

        mock_update_role_data.side_effect = update_role_data

        config = {"aardvark_api_location": "", "connection_iam": {},
                  "active_filters": ["repokid.filters.age:AgeFilter"], "filter_config":
                  {"AgeFilter": {"minimum_age": 90}, "BlacklistFilter": {}}}

        console_logger = logging.StreamHandler()
        console_logger.setLevel(logging.WARNING)

        repokid.cli.repokid_cli.LOGGER = logging.getLogger('test')
        repokid.cli.repokid_cli.LOGGER.addHandler(console_logger)

        dynamo_table = None
        account_number = '123456789012'

        repokid.cli.repokid_cli.update_role_cache(account_number, dynamo_table, config, hooks)

        roles = Roles([Role(ROLES[0]), Role(ROLES[1]), Role(ROLES[2])])

        assert mock_calculate_repo_scores.mock_calls == [call(roles, 90, hooks)]

        # validate update data called for each role
        assert mock_update_role_data.mock_calls == [
            call(dynamo_table, account_number, Role(ROLES[0]), ROLE_POLICIES['all_services_used']),
            call(dynamo_table, account_number, Role(ROLES[1]), ROLE_POLICIES['unused_ec2']),
            call(dynamo_table, account_number, Role(ROLES[2]), ROLE_POLICIES['all_services_used'])]

        # all roles active
        assert mock_find_and_mark_inactive.mock_calls == [call(dynamo_table, account_number,
                                                          [Role(ROLES[0]), Role(ROLES[1]), Role(ROLES[2])])]

        # TODO: validate total permission, repoable, etc are getting updated properly

        assert mock_update_stats.mock_calls == [call(dynamo_table, roles, source='Scan')]

        # TODO: set_role_data called with

    @patch('tabview.view')
    @patch('repokid.cli.repokid_cli.get_role_data')
    @patch('repokid.cli.repokid_cli.role_ids_for_account')
    def test_repokid_display_roles(self, mock_role_ids_for_account, mock_get_role_data, mock_tabview):
        console_logger = logging.StreamHandler()
        console_logger.setLevel(logging.WARNING)

        repokid.cli.repokid_cli.LOGGER = logging.getLogger('test')
        repokid.cli.repokid_cli.LOGGER.addHandler(console_logger)

        mock_role_ids_for_account.return_value = ['AROAABCDEFGHIJKLMNOPA', 'AROAABCDEFGHIJKLMNOPB',
                                                  'AROAABCDEFGHIJKLMNOPC', 'AROAABCDEFGHIJKLMNOPD']

        for x, role in enumerate(ROLES_FOR_DISPLAY):
            role.update(ROLES[x])

        # loop over all roles twice (one for each call below)
        mock_get_role_data.side_effect = [ROLES_FOR_DISPLAY[0], ROLES_FOR_DISPLAY[1], ROLES_FOR_DISPLAY[2],
                                          ROLES_FOR_DISPLAY[3], ROLES_FOR_DISPLAY[0], ROLES_FOR_DISPLAY[1],
                                          ROLES_FOR_DISPLAY[2], ROLES_FOR_DISPLAY[3]]

        repokid.cli.repokid_cli.display_roles('123456789012', None, inactive=True)
        repokid.cli.repokid_cli.display_roles('123456789012', None, inactive=False)

        # first call has inactive role, second doesn't because it's filtered
        assert mock_tabview.mock_calls == [
            call([['Name', 'Refreshed', 'Disqualified By', 'Can be repoed', 'Permissions', 'Repoable', 'Repoed',
                   'Services'],
                  ['all_services_used', "Someday", [], True, 4, 0, 'Never', []],
                  ['inactive_role', "Someday", [], True, 4, 0, 'Never', []],
                  ['young_role', "Someday", [], True, 4, 0, 'Never', []],
                  ['unused_ec2', "Someday", [], True, 4, 2, 'Never', ['ec2']]]),

            call([['Name', 'Refreshed', 'Disqualified By', 'Can be repoed', 'Permissions', 'Repoable', 'Repoed',
                   'Services'],
                  ['all_services_used', "Someday", [], True, 4, 0, 'Never', []],
                  ['young_role', "Someday", [], True, 4, 0, 'Never', []],
                  ['unused_ec2', "Someday", [], True, 4, 2, 'Never', ['ec2']]])]

    @patch('repokid.hooks.call_hooks')
    @patch('repokid.cli.repokid_cli.get_role_data')
    @patch('repokid.cli.repokid_cli.set_role_data')
    @patch('repokid.cli.repokid_cli.role_ids_for_account')
    @patch('time.time')
    def test_schedule_repo(self, mock_time, mock_role_ids_for_account, mock_set_role_data, mock_get_role_data,
                           mock_call_hooks):
        hooks = {}
        mock_role_ids_for_account.return_value = ['AROAABCDEFGHIJKLMNOPA', 'AROAABCDEFGHIJKLMNOPB']
        # first role is not repoable, second role is repoable
        ROLES_FOR_DISPLAY[0].update({'RoleId': 'AROAABCDEFGHIJKLMNOPA'})
        ROLES_FOR_DISPLAY[1].update({'RoleId': 'AROAABCDEFGHIJKLMNOPB'})

        mock_get_role_data.side_effect = [ROLES_FOR_DISPLAY[0], ROLES_FOR_DISPLAY[1]]
        mock_time.return_value = 1

        config = {'repo_schedule_period_days': 1}

        repokid.cli.repokid_cli.schedule_repo('1234567890', None, config, hooks)

        assert mock_set_role_data.mock_calls == [call(None, 'AROAABCDEFGHIJKLMNOPB', {'RepoScheduled': 86401})]
        assert mock_call_hooks.mock_calls == [call(hooks, 'AFTER_SCHEDULE_REPO',
                                              {'roles': [Role(ROLES_FOR_DISPLAY[1])]})]

    @patch('repokid.cli.repokid_cli.get_role_data')
    @patch('repokid.cli.repokid_cli.role_ids_for_account')
    @patch('repokid.cli.repokid_cli.repo_role')
    @patch('time.time')
    def test_repo_all_roles(self, mock_time, mock_repo_role, mock_role_ids_for_account, mock_get_role_data):
        mock_role_ids_for_account.return_value = ['AROAABCDEFGHIJKLMNOPA', 'AROAABCDEFGHIJKLMNOPB',
                                                  'AROAABCDEFGHIJKLMNOPC']
        roles = [{'RoleId': 'AROAABCDEFGHIJKLMNOPA', 'Active': True, 'RoleName': 'ROLE_A', 'RepoScheduled': 100},
                 {'RoleId': 'AROAABCDEFGHIJKLMNOPB', 'Active': True, 'RoleName': 'ROLE_B', 'RepoScheduled': 0},
                 {'RoleId': 'AROAABCDEFGHIJKLMNOPC', 'Active': True, 'RoleName': 'ROLE_C', 'RepoScheduled': 5}]

        # time is past ROLE_C but before ROLE_A
        mock_time.return_value = 10

        # return both roles each time
        mock_get_role_data.side_effect = [roles[0], roles[1], roles[2], roles[0], roles[1], roles[2]]
        mock_repo_role.return_value = None

        # repo all roles in the account, should call repo with all roles
        repokid.cli.repokid_cli.repo_all_roles(None, None, None, None, scheduled=False)
        # repo only scheduled, should only call repo role with role A
        repokid.cli.repokid_cli.repo_all_roles(None, None, None, None, scheduled=True)

        assert mock_repo_role.mock_calls == [call(None, 'ROLE_A', None, None, None, commit=False),
                                             call(None, 'ROLE_B', None, None, None, commit=False),
                                             call(None, 'ROLE_C', None, None, None, commit=False),
                                             call(None, 'ROLE_C', None, None, None, commit=False)]

    def test_generate_default_config(self):
        generated_config = repokid.cli.repokid_cli._generate_default_config()

        required_config_fields = ['filter_config', 'active_filters', 'aardvark_api_location', 'connection_iam',
                                  'dynamo_db', 'logging', 'repo_requirements']

        required_filter_configs = ['AgeFilter', 'BlacklistFilter']

        required_dynamo_config = ['account_number', 'endpoint', 'region', 'session_name']

        required_iam_config = ['assume_role', 'session_name', 'region']

        required_repo_requirements = ['oldest_aa_data_days', 'exclude_new_permissions_for_days']

        assert all(field in generated_config for field in required_config_fields)
        assert all(field in generated_config['filter_config'] for field in required_filter_configs)
        assert all(field in generated_config['dynamo_db'] for field in required_dynamo_config)
        assert all(field in generated_config['connection_iam'] for field in required_iam_config)
        assert all(field in generated_config['repo_requirements'] for field in required_repo_requirements)
        assert 'warnings' in generated_config
