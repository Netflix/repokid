from contextlib import contextmanager
import datetime
import logging
import time
from mock import call, patch
from StringIO import StringIO
import sys

from dateutil.tz import tzlocal

import repokid.repokid
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


@contextmanager
def captured_output():
    new_out, new_err = StringIO(), StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    try:
        sys.stdout, sys.stderr = new_out, new_err
        yield sys.stdout, sys.stderr
    finally:
        sys.stdout, sys.stderr = old_out, old_err


class TestRepokid(object):
    @patch('repokid.utils.roledata.update_stats')
    @patch('repokid.utils.roledata.update_repoable_data')
    @patch('repokid.utils.roledata.update_aardvark_data')
    @patch('repokid.utils.roledata.update_filtered_roles')
    @patch('repokid.utils.roledata.find_and_mark_inactive')
    @patch('repokid.utils.roledata.update_role_data')
    @patch('repokid.repokid._get_aardvark_data')
    @patch('repokid.repokid.get_role_inline_policies')
    @patch('repokid.repokid.list_roles')
    def test_repokid_update_role_cache(self, mock_list_roles, mock_get_role_inline_policies, mock_get_aardvark_data,
                                       mock_update_role_data, mock_find_and_mark_inactive, mock_update_filtered_roles,
                                       mock_update_aardvark_data, mock_update_repoable_data, mock_update_stats):

        # only active roles
        mock_list_roles.return_value = ROLES[:3]

        mock_get_role_inline_policies.side_effect = [ROLE_POLICIES['all_services_used'],
                                                     ROLE_POLICIES['unused_ec2'],
                                                     ROLE_POLICIES['all_services_used']]

        mock_get_aardvark_data.return_value = AARDVARK_DATA

        def update_role_data(role, current_policies):
            role.policies = role.policies = [{'Policy': current_policies}]

        mock_update_role_data.side_effect = update_role_data

        repokid.repokid.CONFIG = {"connection_iam": {},
                                  "active_filters": ["repokid.filters.age:AgeFilter"],
                                  "filter_config": {"AgeFilter": {"minimum_age": 90}}}

        console_logger = logging.StreamHandler()
        console_logger.setLevel(logging.WARNING)

        repokid.repokid.LOGGER = logging.getLogger('test')
        repokid.repokid.LOGGER.addHandler(console_logger)

        repokid.repokid.update_role_cache('123456789012')

        # validate update data called for each role
        assert mock_update_role_data.mock_calls == [call(Role(ROLES[0]), ROLE_POLICIES['all_services_used']),
                                                    call(Role(ROLES[1]), ROLE_POLICIES['unused_ec2']),
                                                    call(Role(ROLES[2]), ROLE_POLICIES['all_services_used'])]

        # all roles active
        assert mock_find_and_mark_inactive.mock_calls == [call('123456789012',
                                                          [Role(ROLES[0]), Role(ROLES[1]), Role(ROLES[2])])]

        roles = Roles([Role(ROLES[0]), Role(ROLES[1]), Role(ROLES[2])])
        assert mock_update_filtered_roles.mock_calls == [call(roles)]

        assert mock_update_aardvark_data.mock_calls == [call(AARDVARK_DATA, roles)]

        # TODO: validate total permission, repoable, etc are getting updated properly
        assert mock_update_repoable_data.mock_calls == [call(roles)]

        assert mock_update_stats.mock_calls == [call(roles, source='Scan')]

    @patch('tabview.view')
    @patch('repokid.utils.roledata.get_role_data')
    @patch('repokid.utils.roledata.role_ids_for_account')
    def test_repokid_display_roles(self, mock_role_ids_for_account, mock_get_role_data, mock_tabview):
        console_logger = logging.StreamHandler()
        console_logger.setLevel(logging.WARNING)

        repokid.repokid.LOGGER = logging.getLogger('test')
        repokid.repokid.LOGGER.addHandler(console_logger)

        mock_role_ids_for_account.return_value = ['AROAABCDEFGHIJKLMNOPA', 'AROAABCDEFGHIJKLMNOPB',
                                                  'AROAABCDEFGHIJKLMNOPC', 'AROAABCDEFGHIJKLMNOPD']

        for x, role in enumerate(ROLES_FOR_DISPLAY):
            role.update(ROLES[x])

        # loop over all roles twice (one for each call below)
        mock_get_role_data.side_effect = [ROLES_FOR_DISPLAY[0], ROLES_FOR_DISPLAY[1], ROLES_FOR_DISPLAY[2],
                                          ROLES_FOR_DISPLAY[3], ROLES_FOR_DISPLAY[0], ROLES_FOR_DISPLAY[1],
                                          ROLES_FOR_DISPLAY[2], ROLES_FOR_DISPLAY[3]]

        repokid.repokid.display_roles('123456789012', inactive=True)
        repokid.repokid.display_roles('123456789012', inactive=False)

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

    def test_generate_default_config(self):
        generated_config = repokid.repokid._generate_default_config()

        required_config_fields = ['filter_config', 'active_filters', 'aardvark_api_location', 'connection_iam',
                                  'dynamo_db', 'logging', 'repo_requirements']

        required_filter_configs = ['AgeFilter', 'BlacklistFilter']

        required_dynamo_config = ['account_number', 'endpoint', 'region', 'session_name']

        required_iam_config = ['assume_role', 'session_name', 'region']

        assert all(field in generated_config for field in required_config_fields)
        assert all(field in generated_config['filter_config'] for field in required_filter_configs)
        assert all(field in generated_config['dynamo_db'] for field in required_dynamo_config)
        assert all(field in generated_config['connection_iam'] for field in required_iam_config)

    @patch('repokid.repokid.expand_policy')
    @patch('repokid.repokid.get_actions_from_statement')
    @patch('repokid.repokid.all_permissions')
    def test_get_role_permissions(self, mock_all_permissions, mock_get_actions_from_statement, mock_expand_policy):
        test_role = Role(ROLES[0])

        all_permissions = ['ec2:associateaddress', 'ec2:attachvolume', 'ec2:createsnapshot', 's3:createbucket',
                           's3:getobject']

        # empty policy to make sure we get the latest
        test_role.policies = [{'Policy': ROLE_POLICIES['all_services_used']}, {'Policy': ROLE_POLICIES['unused_ec2']}]

        mock_all_permissions.return_value = all_permissions
        mock_get_actions_from_statement.return_value = ROLE_POLICIES['unused_ec2']['ec2_perms']
        mock_expand_policy.return_value = ROLE_POLICIES['unused_ec2']['ec2_perms']

        permissions = repokid.repokid._get_role_permissions(test_role)
        assert permissions == set(ROLE_POLICIES['unused_ec2']['ec2_perms'])

    def test_get_repoable_permissions(self):
        repokid.repokid.CONFIG = {'filter_config': {'AgeFilter': {'minimum_age': 1}}}
        repokid.repokid.IAM_ACCESS_ADVISOR_UNSUPPORTED_SERVICES = ['service_2']
        repokid.repokid.IAM_ACCESS_ADVISOR_UNSUPPORTED_ACTIONS = ['service_1:action_3', 'service_1:action_4']

        permissions = ['service_1:action_1', 'service_1:action_2', 'service_1:action_3', 'service_1:action_4',
                       'service_2:action_1', 'service_3:action_1', 'service_3:action_2']

        aa_data = [{'serviceNamespace': 'service_1', 'lastAuthenticated': (time.time() - 90000) * 1000},
                   {'serviceNamespace': 'service_2', 'lastAuthenticated': (time.time() - 90000) * 1000},
                   {'serviceNamespace': 'service_3', 'lastAuthenticated': time.time() * 1000}]

        repoable_permissions = repokid.repokid._get_repoable_permissions(permissions, aa_data)
        # service_1:action_3 and action_4 are unsupported actions, service_2 is an unsupported service, service_3
        # was used too recently
        assert repoable_permissions == set(['service_1:action_1', 'service_1:action_2'])

    @patch('repokid.repokid._get_role_permissions')
    @patch('repokid.repokid._get_repoable_permissions')
    def test_calculate_repo_scores(self, mock_get_repoable_permissions, mock_get_role_permissions):
        roles = [Role(ROLES[0]), Role(ROLES[1]), Role(ROLES[2])]
        roles[0].disqualified_by = []
        roles[0].aa_data = 'some_aa_data'

        # disqualified by a filter
        roles[1].policies = [{'Policy': ROLE_POLICIES['unused_ec2']}]
        roles[1].disqualified_by = ['some_filter']
        roles[1].aa_data = 'some_aa_data'

        # no AA data
        roles[2].policies = [{'Policy': ROLE_POLICIES['all_services_used']}]
        roles[2].disqualified_by = []
        roles[2].aa_data = None

        mock_get_role_permissions.side_effect = [['iam:AddRoleToInstanceProfile', 'iam:AttachRolePolicy',
                                                  'ec2:AllocateHosts', 'ec2:AssociateAddress'],
                                                 ['iam:AddRoleToInstanceProfile', 'iam:AttachRolePolicy'],
                                                 ['iam:AddRoleToInstanceProfile', 'iam:AttachRolePolicy']]

        mock_get_repoable_permissions.side_effect = [set(['iam:AddRoleToInstanceProfile', 'iam:AttachRolePolicy'])]

        repokid.repokid._calculate_repo_scores(roles)

        assert roles[0].repoable_permissions == 2
        assert roles[0].repoable_services == ['iam']
        assert roles[1].repoable_permissions == 0
        assert roles[1].repoable_services == []
        assert roles[2].repoable_permissions == 0
        assert roles[2].repoable_services == []

    def test_get_repoed_policy(self):
        policies = ROLE_POLICIES['all_services_used']
        repoable_permissions = set(['iam:addroletoinstanceprofile', 'iam:attachrolepolicy', 's3:createbucket'])

        rewritten_policies, empty_policies = repokid.repokid._get_repoed_policy(policies, repoable_permissions)

        assert rewritten_policies == {'s3_perms': {'Version': '2012-10-17',
                                                   'Statement': [{'Action': ['s3:deletebucket'],
                                                                  'Resource': ['*'],
                                                                  'Effect': 'Allow'}]}}
        assert empty_policies == ['iam_perms']
