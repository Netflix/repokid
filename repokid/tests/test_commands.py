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
import datetime
import logging
import time

from dateutil.tz import tzlocal
from mock import MagicMock
from mock import call
from mock import mock_open
from mock import patch
from pytest import raises

import repokid.cli.repokid_cli
import repokid.commands.repo
import repokid.commands.role
import repokid.commands.role_cache
import repokid.commands.schedule
import repokid.utils.iam
import repokid.utils.logging
import repokid.utils.roledata
from repokid.exceptions import IAMError
from repokid.role import Role
from repokid.role import RoleList
from repokid.types import RepokidHooks

AARDVARK_DATA = {
    "arn:aws:iam::123456789012:role/all_services_used": [
        {"lastAuthenticated": int(time.time()) * 1000, "serviceNamespace": "iam"},
        {"lastAuthenticated": int(time.time()) * 1000, "serviceNamespace": "s3"},
    ],
    "arn:aws:iam::123456789012:role/unused_ec2": [
        {"lastAuthenticated": int(time.time()) * 1000, "serviceNamespace": "iam"},
        {"lastAuthenticated": 0, "serviceNamespace": "ec2"},
    ],
    "arn:aws:iam::123456789012:role/young_role": [
        {"lastAuthenticated": int(time.time()) * 1000, "serviceNamespace": "iam"},
        {"lastAuthenticated": int(time.time()) * 1000, "serviceNamespace": "s3"},
    ],
    "arn:aws:iam::123456789012:role/additional_unused_ec2": [
        {"lastAuthenticated": int(time.time()) * 1000, "serviceNamespace": "iam"},
        {"lastAuthenticated": 0, "serviceNamespace": "ec2"},
        {"lastAuthenticated": 0, "serviceNamespace": "unsupported_service"},
        {"lastAuthenticated": 0, "serviceNamespace": "supported_service"},
    ],
    "arn:aws:iam::123456789012:role/unused_iam": [
        {"lastAuthenticated": 0, "serviceNamespace": "iam"},
        {"lastAuthenticated": int(time.time()) * 1000, "serviceNamespace": "ec2"},
    ],
}

ROLE_POLICIES = {
    "all_services_used": {
        "iam_perms": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": ["iam:AddRoleToInstanceProfile", "iam:AttachRolePolicy"],
                    "Resource": ["*"],
                    "Effect": "Allow",
                }
            ],
        },
        "s3_perms": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": ["s3:CreateBucket", "s3:DeleteBucket"],
                    "Resource": ["*"],
                    "Effect": "Allow",
                }
            ],
        },
    },
    "unused_ec2": {
        "iam_perms": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": ["iam:AddRoleToInstanceProfile", "iam:AttachRolePolicy"],
                    "Resource": ["*"],
                    "Effect": "Allow",
                }
            ],
        },
        "ec2_perms": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": ["ec2:AllocateHosts", "ec2:AssociateAddress"],
                    "Resource": ["*"],
                    "Effect": "Allow",
                }
            ],
        },
    },
    "additional_unused_ec2": {
        "iam_perms": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": ["iam:AddRoleToInstanceProfile", "iam:AttachRolePolicy"],
                    "Resource": ["*"],
                    "Effect": "Allow",
                }
            ],
        },
        "ec2_perms": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": ["ec2:AllocateHosts", "ec2:AssociateAddress"],
                    "Resource": ["*"],
                    "Effect": "Allow",
                }
            ],
        },
    },
    "unused_iam": {
        "iam_perms": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": ["iam:AddRoleToInstanceProfile", "iam:AttachRolePolicy"],
                    "Resource": ["*"],
                    "Effect": "Allow",
                }
            ],
        },
        "ec2_perms": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": ["ec2:AllocateHosts", "ec2:AssociateAddress"],
                    "Resource": ["*"],
                    "Effect": "Allow",
                }
            ],
        },
    },
}

ROLES = [
    {
        "Account": "123456789012",
        "Arn": "arn:aws:iam::123456789012:role/all_services_used",
        "CreateDate": datetime.datetime(2017, 1, 31, 12, 0, 0, tzinfo=tzlocal()),
        "RoleId": "AROAABCDEFGHIJKLMNOPA",
        "RoleName": "all_services_used",
        "Active": True,
    },
    {
        "Account": "123456789012",
        "Arn": "arn:aws:iam::123456789012:role/unused_ec2",
        "CreateDate": datetime.datetime(2017, 1, 31, 12, 0, 0, tzinfo=tzlocal()),
        "RoleId": "AROAABCDEFGHIJKLMNOPB",
        "RoleName": "unused_ec2",
        "Active": True,
    },
    {
        "Account": "123456789012",
        "Arn": "arn:aws:iam::123456789012:role/young_role",
        "CreateDate": datetime.datetime.now(tzlocal()) - datetime.timedelta(5),
        "RoleId": "AROAABCDEFGHIJKLMNOPC",
        "RoleName": "young_role",
        "Active": True,
    },
    {
        "Account": "123456789012",
        "Arn": "arn:aws:iam::123456789012:role/inactive_role",
        "CreateDate": datetime.datetime.now(tzlocal()) - datetime.timedelta(5),
        "RoleId": "AROAABCDEFGHIJKLMNOPD",
        "RoleName": "inactive_role",
        "Active": False,
    },
    {
        "Account": "123456789012",
        "Arn": "arn:aws:iam::123456789012:role/additional_unused_ec2",
        "CreateDate": datetime.datetime(2017, 1, 31, 12, 0, 0, tzinfo=tzlocal()),
        "RoleId": "AROAXYZDEFGHIJKLMNOPB",
        "RoleName": "unused_ec2",
        "Active": True,
    },
    {
        "Account": "123456789012",
        "Arn": "arn:aws:iam::123456789012:role/unused_iam",
        "CreateDate": datetime.datetime(2017, 1, 31, 12, 0, 0, tzinfo=tzlocal()),
        "RoleId": "AROAXYZDEFGHIJKLMNABC",
        "RoleName": "unused_ec2",
        "Active": True,
    },
]

ROLES_FOR_DISPLAY = [
    Role.parse_obj(
        {
            "TotalPermissions": 4,
            "RepoablePermissions": 0,
            "Repoed": "Never",
            "RepoableServices": [],
            "Refreshed": "Someday",
        }
    ),
    Role.parse_obj(
        {
            "TotalPermissions": 4,
            "RepoablePermissions": 2,
            "Repoed": "Never",
            "RepoableServices": ["ec2"],
            "Refreshed": "Someday",
        }
    ),
    Role.parse_obj(
        {
            "TotalPermissions": 4,
            "RepoablePermissions": 0,
            "Repoed": "Never",
            "RepoableServices": [],
            "Refreshed": "Someday",
        }
    ),
    Role.parse_obj(
        {
            "TotalPermissions": 4,
            "RepoablePermissions": 0,
            "Repoed": "Never",
            "RepoableServices": [],
            "Refreshed": "Someday",
        }
    ),
    Role.parse_obj(
        {
            "TotalPermissions": 4,
            "RepoablePermissions": 2,
            "Repoed": "Never",
            "RepoableServices": ["ec2"],
            "Refreshed": "Someday",
        }
    ),
    Role.parse_obj(
        {
            "TotalPermissions": 4,
            "RepoablePermissions": 2,
            "Repoed": "Never",
            "RepoableServices": ["ec2"],
            "Refreshed": "Someday",
        }
    ),
]


class TestRepokidCLI(object):
    @patch("repokid.commands.role_cache.roledata.update_stats")
    @patch("repokid.commands.role_cache.roledata.find_and_mark_inactive")
    @patch("repokid.commands.role_cache.roledata.update_role_data")
    @patch("repokid.commands.role_cache.roledata._calculate_repo_scores")
    @patch("repokid.commands.role_cache.set_role_data")
    @patch("repokid.commands.role_cache.get_aardvark_data")
    @patch("repokid.commands.role_cache.get_account_authorization_details")
    def test_repokid_update_role_cache(
        self,
        mock_get_account_authorization_details,
        mock_get_aardvark_data,
        mock_set_role_data,
        mock_calculate_repo_scores,
        mock_update_role_data,
        mock_find_and_mark_inactive,
        mock_update_stats,
    ):

        hooks = {}

        role_data = ROLES[:3]
        role_data[0]["RolePolicyList"] = [
            {
                "PolicyName": "all_services_used",
                "PolicyDocument": ROLE_POLICIES["all_services_used"],
            }
        ]
        role_data[1]["RolePolicyList"] = [
            {"PolicyName": "unused_ec2", "PolicyDocument": ROLE_POLICIES["unused_ec2"]}
        ]
        role_data[2]["RolePolicyList"] = [
            {
                "PolicyName": "all_services_used",
                "PolicyDocument": ROLE_POLICIES["all_services_used"],
            }
        ]

        mock_get_account_authorization_details.side_effect = [role_data]
        mock_get_aardvark_data.return_value = AARDVARK_DATA

        def update_role_data(dynamo_table, account_number, role, current_policies):
            role.policies = [{"Policy": current_policies}]
            return role

        mock_update_role_data.side_effect = update_role_data

        config = {
            "aardvark_api_location": "",
            "connection_iam": {},
            "active_filters": ["repokid.filters.age:AgeFilter"],
            "filter_config": {"AgeFilter": {"minimum_age": 90}, "BlocklistFilter": {}},
        }

        console_logger = logging.StreamHandler()
        console_logger.setLevel(logging.WARNING)

        repokid.cli.repokid_cli.logger = logging.getLogger("test")
        repokid.cli.repokid_cli.logger.addHandler(console_logger)

        dynamo_table = None
        account_number = "123456789012"

        repokid.commands.role_cache._update_role_cache(
            account_number, dynamo_table, config, hooks
        )

        roles = RoleList(
            [
                Role.parse_obj(ROLES[0]),
                Role.parse_obj(ROLES[1]),
                Role.parse_obj(ROLES[2]),
            ]
        )

        assert mock_calculate_repo_scores.mock_calls == [
            call(roles, 90, hooks, False, 100)
        ]

        # validate update data called for each role
        assert mock_update_role_data.mock_calls == [
            call(
                dynamo_table,
                account_number,
                Role.parse_obj(ROLES[0]),
                {"all_services_used": ROLE_POLICIES["all_services_used"]},
            ),
            call(
                dynamo_table,
                account_number,
                Role.parse_obj(ROLES[1]),
                {"unused_ec2": ROLE_POLICIES["unused_ec2"]},
            ),
            call(
                dynamo_table,
                account_number,
                Role.parse_obj(ROLES[2]),
                {"all_services_used": ROLE_POLICIES["all_services_used"]},
            ),
        ]

        # all roles active
        assert mock_find_and_mark_inactive.mock_calls == [
            call(
                dynamo_table,
                account_number,
                RoleList(
                    [
                        Role.parse_obj(ROLES[0]),
                        Role.parse_obj(ROLES[1]),
                        Role.parse_obj(ROLES[2]),
                    ]
                ),
            )
        ]

        # TODO: validate total permission, repoable, etc are getting updated properly

        assert mock_update_stats.mock_calls == [
            call(dynamo_table, roles, source="Scan")
        ]

        # TODO: set_role_data called with

    @patch("tabview.view")
    @patch("repokid.commands.role.get_role_data")
    @patch("repokid.commands.role.role_ids_for_account")
    def test_repokid_display_roles(
        self, mock_role_ids_for_account, mock_get_role_data, mock_tabview
    ):
        console_logger = logging.StreamHandler()
        console_logger.setLevel(logging.WARNING)

        repokid.cli.repokid_cli.logger = logging.getLogger("test")
        repokid.cli.repokid_cli.logger.addHandler(console_logger)

        mock_role_ids_for_account.return_value = [
            "AROAABCDEFGHIJKLMNOPA",
            "AROAABCDEFGHIJKLMNOPB",
            "AROAABCDEFGHIJKLMNOPC",
            "AROAABCDEFGHIJKLMNOPD",
        ]

        test_roles = []
        for x, role in enumerate(ROLES_FOR_DISPLAY):
            test_roles.append(
                role.copy(update=Role.parse_obj(ROLES[x]).dict(exclude_unset=True))
            )

        # loop over all roles twice (one for each call below)
        mock_get_role_data.side_effect = [
            test_roles[0],
            test_roles[1],
            test_roles[2],
            test_roles[3],
            test_roles[0],
            test_roles[1],
            test_roles[2],
            test_roles[3],
        ]

        repokid.commands.role._display_roles("123456789012", None, inactive=True)
        repokid.commands.role._display_roles("123456789012", None, inactive=False)

        # first call has inactive role, second doesn't because it's filtered
        assert mock_tabview.mock_calls == [
            call(
                [
                    [
                        "Name",
                        "Refreshed",
                        "Disqualified By",
                        "Can be repoed",
                        "Permissions",
                        "Repoable",
                        "Repoed",
                        "Services",
                    ],
                    ["all_services_used", "Someday", [], True, 4, 0, "Never", []],
                    ["inactive_role", "Someday", [], True, 4, 0, "Never", []],
                    ["young_role", "Someday", [], True, 4, 0, "Never", []],
                    ["unused_ec2", "Someday", [], True, 4, 2, "Never", ["ec2"]],
                ]
            ),
            call(
                [
                    [
                        "Name",
                        "Refreshed",
                        "Disqualified By",
                        "Can be repoed",
                        "Permissions",
                        "Repoable",
                        "Repoed",
                        "Services",
                    ],
                    ["all_services_used", "Someday", [], True, 4, 0, "Never", []],
                    ["young_role", "Someday", [], True, 4, 0, "Never", []],
                    ["unused_ec2", "Someday", [], True, 4, 2, "Never", ["ec2"]],
                ]
            ),
        ]

    @patch("repokid.hooks.call_hooks")
    @patch("repokid.commands.schedule.get_role_data")
    @patch("repokid.commands.schedule.set_role_data")
    @patch("repokid.commands.schedule.role_ids_for_account")
    @patch("time.time")
    def test_schedule_repo(
        self,
        mock_time,
        mock_role_ids_for_account,
        mock_set_role_data,
        mock_get_role_data,
        mock_call_hooks,
    ):
        hooks = RepokidHooks
        mock_role_ids_for_account.return_value = [
            "AROAABCDEFGHIJKLMNOPA",
            "AROAABCDEFGHIJKLMNOPB",
        ]
        # first role is not repoable, second role is repoable
        test_roles = [
            ROLES_FOR_DISPLAY[0].copy(
                update=Role.parse_obj({"RoleId": "AROAABCDEFGHIJKLMNOPA"}).dict(
                    exclude_unset=True
                )
            ),
            ROLES_FOR_DISPLAY[1].copy(
                update=Role.parse_obj(
                    {"RoleId": "AROAABCDEFGHIJKLMNOPB", "AAData": [{"foo": "bar"}]}
                ).dict(exclude_unset=True)
            ),
        ]
        mock_get_role_data.side_effect = [test_roles[0], test_roles[1]]
        mock_time.return_value = 1

        config = {"repo_schedule_period_days": 1}

        repokid.commands.schedule._schedule_repo("1234567890", None, config, hooks)

        assert mock_set_role_data.mock_calls == [
            call(
                None,
                "AROAABCDEFGHIJKLMNOPB",
                {"RepoScheduled": 86401, "ScheduledPerms": ["ec2"]},
            )
        ]
        assert mock_call_hooks.mock_calls == [
            call(
                hooks,
                "AFTER_SCHEDULE_REPO",
                {"roles": [test_roles[1]]},
            )
        ]

    @patch("repokid.hooks.call_hooks")
    @patch("repokid.commands.repo.get_role_data")
    @patch("repokid.commands.repo.role_ids_for_account")
    @patch("repokid.commands.repo._repo_role")
    @patch("time.time")
    def test_repo_all_roles(
        self,
        mock_time,
        mock_repo_role,
        mock_role_ids_for_account,
        mock_get_role_data,
        mock_call_hooks,
    ):
        hooks = RepokidHooks()
        mock_role_ids_for_account.return_value = [
            "AROAABCDEFGHIJKLMNOPA",
            "AROAABCDEFGHIJKLMNOPB",
            "AROAABCDEFGHIJKLMNOPC",
        ]
        roles = RoleList(
            [
                Role.parse_obj(
                    {
                        "Arn": "arn:aws:iam::123456789012:role/ROLE_A",
                        "RoleId": "AROAABCDEFGHIJKLMNOPA",
                        "Active": True,
                        "RoleName": "ROLE_A",
                        "RepoScheduled": 100,
                        "CreateDate": datetime.datetime.now()
                        - datetime.timedelta(days=100),
                    }
                ),
                Role.parse_obj(
                    {
                        "Arn": "arn:aws:iam::123456789012:role/ROLE_B",
                        "RoleId": "AROAABCDEFGHIJKLMNOPB",
                        "Active": True,
                        "RoleName": "ROLE_B",
                        "RepoScheduled": 0,
                        "CreateDate": datetime.datetime.now()
                        - datetime.timedelta(days=100),
                    }
                ),
                Role.parse_obj(
                    {
                        "Arn": "arn:aws:iam::123456789012:role/ROLE_C",
                        "RoleId": "AROAABCDEFGHIJKLMNOPC",
                        "Active": True,
                        "RoleName": "ROLE_C",
                        "RepoScheduled": 5,
                        "CreateDate": datetime.datetime.now()
                        - datetime.timedelta(days=100),
                    }
                ),
            ]
        )

        # time is past ROLE_C but before ROLE_A
        mock_time.return_value = 10

        # return both roles each time
        mock_get_role_data.side_effect = [
            roles[0],
            roles[1],
            roles[2],
            roles[0],
            roles[1],
            roles[2],
        ]
        mock_repo_role.return_value = None

        # repo all roles in the account, should call repo with all roles
        repokid.commands.repo._repo_all_roles("", None, {}, hooks, scheduled=False)
        # repo only scheduled, should only call repo role with role C
        repokid.commands.repo._repo_all_roles("", None, {}, hooks, scheduled=True)

        assert mock_repo_role.mock_calls == [
            call("", "ROLE_A", None, {}, hooks, commit=False, scheduled=False),
            call("", "ROLE_B", None, {}, hooks, commit=False, scheduled=False),
            call("", "ROLE_C", None, {}, hooks, commit=False, scheduled=False),
            call("", "ROLE_C", None, {}, hooks, commit=False, scheduled=True),
        ]

        assert mock_call_hooks.mock_calls == [
            call(
                hooks,
                "BEFORE_REPO_ROLES",
                {"account_number": "", "roles": roles},
            ),
            call(
                hooks,
                "AFTER_REPO_ROLES",
                {"account_number": "", "roles": roles, "errors": []},
            ),
            call(
                hooks,
                "BEFORE_REPO_ROLES",
                {"account_number": "", "roles": RoleList([roles[2]])},
            ),
            call(
                hooks,
                "AFTER_REPO_ROLES",
                {
                    "account_number": "",
                    "roles": RoleList([roles[2]]),
                    "errors": [],
                },
            ),
        ]

    @patch("repokid.commands.schedule.find_role_in_cache")
    @patch("repokid.commands.schedule.get_role_data")
    @patch("repokid.commands.schedule.role_ids_for_account")
    @patch("repokid.commands.schedule.set_role_data")
    def test_cancel_scheduled_repo(
        self,
        mock_set_role_data,
        mock_role_ids_for_account,
        mock_get_role_data,
        mock_find_role_in_cache,
    ):

        mock_role_ids_for_account.return_value = [
            "AROAABCDEFGHIJKLMNOPA",
            "AROAABCDEFGHIJKLMNOPB",
        ]
        roles = RoleList(
            [
                Role.parse_obj(
                    {
                        "Arn": "arn:aws:iam::123456789012:role/ROLE_A",
                        "RoleId": "AROAABCDEFGHIJKLMNOPA",
                        "Active": True,
                        "RoleName": "ROLE_A",
                        "RepoScheduled": 100,
                        "CreateDate": datetime.datetime.now()
                        - datetime.timedelta(days=100),
                    }
                ),
                Role.parse_obj(
                    {
                        "Arn": "arn:aws:iam::123456789012:role/ROLE_B",
                        "RoleId": "AROAABCDEFGHIJKLMNOPB",
                        "Active": True,
                        "RoleName": "ROLE_B",
                        "RepoScheduled": 0,
                        "CreateDate": datetime.datetime.now()
                        - datetime.timedelta(days=100),
                    }
                ),
                Role.parse_obj(
                    {
                        "Arn": "arn:aws:iam::123456789012:role/ROLE_C",
                        "RoleId": "AROAABCDEFGHIJKLMNOPC",
                        "Active": True,
                        "RoleName": "ROLE_C",
                        "RepoScheduled": 5,
                        "CreateDate": datetime.datetime.now()
                        - datetime.timedelta(days=100),
                    }
                ),
            ]
        )
        mock_get_role_data.side_effect = [roles[0], roles[2], roles[0]]

        # first check all
        repokid.commands.schedule._cancel_scheduled_repo(
            None, None, role_name=None, is_all=True
        )

        # ensure all are cancelled
        mock_find_role_in_cache.return_value = ["AROAABCDEFGHIJKLMNOPA"]

        repokid.commands.schedule._cancel_scheduled_repo(
            None, None, role_name="ROLE_A", is_all=False
        )

        assert mock_set_role_data.mock_calls == [
            call(
                None,
                "AROAABCDEFGHIJKLMNOPA",
                {"RepoScheduled": 0, "ScheduledPerms": []},
            ),
            call(
                None,
                "AROAABCDEFGHIJKLMNOPC",
                {"RepoScheduled": 0, "ScheduledPerms": []},
            ),
            call(
                None,
                "AROAABCDEFGHIJKLMNOPA",
                {"RepoScheduled": 0, "ScheduledPerms": []},
            ),
        ]

    def test_generate_default_config(self):
        generated_config = repokid.cli.repokid_cli._generate_default_config()

        required_config_fields = [
            "filter_config",
            "active_filters",
            "aardvark_api_location",
            "connection_iam",
            "dynamo_db",
            "logging",
            "repo_requirements",
        ]

        required_filter_configs = ["AgeFilter", "BlocklistFilter"]

        required_dynamo_config = [
            "account_number",
            "endpoint",
            "region",
            "session_name",
        ]

        required_iam_config = ["assume_role", "session_name", "region"]

        required_repo_requirements = [
            "oldest_aa_data_days",
            "exclude_new_permissions_for_days",
        ]

        assert all(field in generated_config for field in required_config_fields)
        assert all(
            field in generated_config["filter_config"]
            for field in required_filter_configs
        )
        assert all(
            field in generated_config["dynamo_db"] for field in required_dynamo_config
        )
        assert all(
            field in generated_config["connection_iam"] for field in required_iam_config
        )
        assert all(
            field in generated_config["repo_requirements"]
            for field in required_repo_requirements
        )
        assert "warnings" in generated_config

    def test_inline_policies_size_exceeds_maximum(self):
        small_policy = dict()
        assert not repokid.utils.iam.inline_policies_size_exceeds_maximum(small_policy)

        backup_size = repokid.utils.iam.MAX_AWS_POLICY_SIZE
        repokid.utils.iam.MAX_AWS_POLICY_SIZE = 10
        assert repokid.utils.iam.inline_policies_size_exceeds_maximum(
            ROLE_POLICIES["all_services_used"]
        )
        repokid.utils.iam.MAX_AWS_POLICY_SIZE = backup_size

    def test_logprint_deleted_and_repoed_policies(self):
        # TODO: When moving to python >= 3.4, Replace this with assertLogs
        # https://stackoverflow.com/questions/899067/how-should-i-verify-a-log-message-when-testing-python-code-under-nose
        class MockLoggingHandler(logging.Handler):
            """Mock logging handler to check for expected logs."""

            def __init__(self, *args, **kwargs):
                self.reset()
                logging.Handler.__init__(self, *args, **kwargs)

            def emit(self, record):
                self.messages[record.levelname.lower()].append(record.getMessage())

            def reset(self):
                self.messages = {
                    "debug": [],
                    "info": [],
                    "warning": [],
                    "error": [],
                    "critical": [],
                }

        repokid.utils.logging.LOGGER = logging.getLogger("test")
        mock_logger = MockLoggingHandler()
        repokid.utils.logging.LOGGER.addHandler(mock_logger)
        repokid.utils.logging.LOGGER.setLevel(logging.DEBUG)

        policy_names = ["policy1", "policy2"]
        repoed_policies = [ROLE_POLICIES]
        repokid.utils.logging.log_deleted_and_repoed_policies(
            policy_names, repoed_policies, "MyRoleName", "123456789012"
        )
        assert len(mock_logger.messages["info"]) == 3
        assert "policy1" in mock_logger.messages["info"][0]
        assert "policy2" in mock_logger.messages["info"][1]
        assert "all_services_used" in mock_logger.messages["info"][2]

    def test_delete_policy(self):
        iam = repokid.utils.iam

        def mock_delete_role_policy(RoleName, PolicyName, **conn):
            import botocore

            raise botocore.exceptions.ClientError(
                dict(Error=dict(Code="TESTING")), "TESTING"
            )

        class MockRole:
            role_name = "role_name"

        iam.delete_role_policy = mock_delete_role_policy
        mock_role = MockRole()

        with raises(IAMError):
            repokid.utils.iam.delete_policy(
                "PolicyName", mock_role, "123456789012", dict()
            )

    def test_replace_policies(self):
        iam = repokid.utils.iam

        def mock_put_role_policy(RoleName, PolicyName, PolicyDocument, **conn):
            import botocore

            raise botocore.exceptions.ClientError(
                dict(Error=dict(Code="TESTING")), "TESTING"
            )

        class MockRole:
            role_name = "role_name"

        iam.put_role_policy = mock_put_role_policy
        mock_role = MockRole()

        with raises(IAMError):
            repokid.utils.iam.replace_policies(
                ROLE_POLICIES, mock_role, "123456789012", {}
            )

    @patch("repokid.utils.iam.delete_policy", MagicMock(return_value=None))
    @patch("repokid.utils.iam.replace_policies", MagicMock(return_value=None))
    @patch(
        "repokid.utils.iam.remove_permissions_from_role", MagicMock(return_value=None)
    )
    @patch("repokid.utils.iam.get_role_inline_policies", MagicMock(return_value=None))
    @patch(
        "repokid.utils.iam.roledata.add_new_policy_version",
        MagicMock(return_value=None),
    )
    @patch("repokid.utils.iam.set_role_data", MagicMock(return_value=None))
    @patch("repokid.utils.iam.set_role_data", MagicMock(return_value=None))
    @patch(
        "repokid.utils.iam.update_repoed_description",
        MagicMock(return_value=None),
    )
    @patch("repokid.utils.iam.roledata.update_role_data", MagicMock(return_value=None))
    def test_remove_permissions_from_role(self):
        iam = repokid.utils.iam

        class MockRole:
            role_name = "role_name"
            role_id = "12345-roleid"
            policies = [
                dict(Policy=policy) for _, policy in list(ROLE_POLICIES.items())
            ]

            def as_dict(self):
                return dict(RoleName=self.role_name, policies=self.policies)

        mock_role = MockRole()

        iam.remove_permissions_from_role(
            "123456789012",
            ["s3:putobjectacl"],
            mock_role,
            "12345-roleid",
            None,
            None,
            None,
            commit=False,
        )

        iam.remove_permissions_from_role(
            "123456789012",
            ["s3:putobjectacl"],
            mock_role,
            "12345-roleid",
            None,
            {"connection_iam": dict()},
            None,
            commit=True,
        )

    @patch(
        "repokid.commands.role.find_role_in_cache",
        MagicMock(return_value="12345-roleid"),
    )
    @patch("repokid.commands.role.get_role_data", MagicMock(return_value=None))
    @patch(
        "repokid.commands.role.remove_permissions_from_role",
        MagicMock(return_value=None),
    )
    @patch("repokid.commands.role.repokid.hooks")
    def test_remove_permissions_from_roles(self, mock_hooks):
        import json

        arns = [role["Arn"] for role in ROLES]
        arns = json.dumps(arns)

        class Hooks:
            def call_hooks(hooks, tag, role_dict):
                assert tag == "AFTER_REPO"

        mock_hooks = Hooks()

        with patch("builtins.open", mock_open(read_data=arns)) as mock_file:
            assert open("somefile.json").read() == arns
            mock_file.assert_called_with("somefile.json")
            repokid.commands.role._remove_permissions_from_roles(
                ["s3:putobjectacl"],
                "somefile.json",
                None,
                None,
                mock_hooks,
                commit=False,
            )
