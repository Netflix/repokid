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
import time
from unittest.mock import patch

import repokid.utils.roledata
from repokid.role import Role
from repokid.tests.test_commands import AARDVARK_DATA
from repokid.tests.test_commands import ROLE_POLICIES
from repokid.tests.test_commands import ROLES

# AARDVARK_DATA maintained in test_repokid_cli


class TestRoledata(object):
    @patch("repokid.utils.roledata.expand_policy")
    @patch("repokid.utils.roledata.get_actions_from_statement")
    @patch("repokid.utils.roledata.all_permissions")
    def test_get_role_permissions(
        self, mock_all_permissions, mock_get_actions_from_statement, mock_expand_policy
    ):
        test_role = Role.parse_obj(ROLES[0])

        all_permissions = [
            "ec2:associateaddress",
            "ec2:attachvolume",
            "ec2:createsnapshot",
            "s3:createbucket",
            "s3:getobject",
        ]

        # empty policy to make sure we get the latest
        test_role.policies = [
            {"Policy": ROLE_POLICIES["all_services_used"]},
            {"Policy": ROLE_POLICIES["unused_ec2"]},
        ]

        mock_all_permissions.return_value = all_permissions
        mock_get_actions_from_statement.return_value = ROLE_POLICIES["unused_ec2"][
            "ec2_perms"
        ]["Statement"][0]["Action"]
        mock_expand_policy.return_value = ROLE_POLICIES["unused_ec2"]["ec2_perms"]

        (
            total_permissions,
            eligible_permissions,
        ) = repokid.utils.roledata._get_role_permissions(test_role)
        assert total_permissions == set(
            ROLE_POLICIES["unused_ec2"]["ec2_perms"]["Statement"][0]["Action"]
        )
        assert eligible_permissions == set(
            ROLE_POLICIES["unused_ec2"]["ec2_perms"]["Statement"][0]["Action"]
        )

    @patch("repokid.hooks.call_hooks")
    def test_get_repoable_permissions(self, mock_call_hooks):
        minimum_age = 1
        repokid.utils.roledata.IAM_ACCESS_ADVISOR_UNSUPPORTED_SERVICES = ["service_2"]
        repokid.utils.roledata.IAM_ACCESS_ADVISOR_UNSUPPORTED_ACTIONS = [
            "service_1:action_3",
            "service_1:action_4",
        ]

        hooks = {}

        role_id = "ARIOTHISISAROLE"
        permissions = {
            "service_1:action_1",
            "service_1:action_2",
            "service_1:action_3",
            "service_1:action_4",
            "service_2:action_1",
            "service_3:action_1",
            "service_3:action_2",
            "service_4:action_1",
            "service_4:action_2",
        }

        # service_1 and service_2 both used more than a day ago, which is outside of our test filter for age
        aa_data = [
            {
                "serviceNamespace": "service_1",
                "lastAuthenticated": (time.time() - 90000) * 1000,
            },
            {
                "serviceNamespace": "service_2",
                "lastAuthenticated": (time.time() - 90000) * 1000,
            },
            {"serviceNamespace": "service_3", "lastAuthenticated": time.time() * 1000},
        ]

        no_repo_permissions = {
            "service_4:action_1": time.time() - 1,
            "service_4:action_2": time.time() + 1000,
        }

        true_repoable_decision = repokid.utils.roledata.RepoablePermissionDecision()
        true_repoable_decision.repoable = True

        false_repoable_decision = repokid.utils.roledata.RepoablePermissionDecision()
        false_repoable_decision.repoable = False

        mock_call_hooks.return_value = {
            "potentially_repoable_permissions": {
                "service_1:action_1": true_repoable_decision,
                "service_1:action_2": true_repoable_decision,
                "service_4:action_1": true_repoable_decision,
                "service_1:action_3": false_repoable_decision,
                "service_1:action_4": false_repoable_decision,
                "service_2:action_1": false_repoable_decision,
                "service_3:action_1": false_repoable_decision,
                "service_3:action_2": false_repoable_decision,
                "service_4:action_2": false_repoable_decision,
            }
        }

        repoable_permissions = repokid.utils.roledata._get_repoable_permissions(
            None,
            "test_name",
            permissions,
            aa_data,
            no_repo_permissions,
            role_id,
            minimum_age,
            hooks,
        )
        # service_1:action_3 and action_4 are unsupported actions, service_2 is an unsupported service, service_3
        # was used too recently, service_4 action 2 is in no_repo_permissions and not expired
        assert repoable_permissions == {
            "service_1:action_1",
            "service_1:action_2",
            "service_4:action_1",
        }

    @patch("repokid.hooks.call_hooks")
    def test_get_repoable_permissions_batch(self, mock_call_hooks):
        roles = [
            Role.parse_obj(ROLES[0]),
            Role.parse_obj(ROLES[4]),
            Role.parse_obj(ROLES[5]),
        ]

        roles[0].aa_data = AARDVARK_DATA[roles[0].arn]
        roles[1].no_repo_permissions = {
            "ec2:AllocateHosts": time.time() - 1,
            "ec2:AssociateAddress": time.time() + 1000,
        }
        roles[1].aa_data = AARDVARK_DATA[roles[1].arn]
        roles[2].aa_data = AARDVARK_DATA[roles[2].arn]

        minimum_age = 1
        repokid.utils.roledata.IAM_ACCESS_ADVISOR_UNSUPPORTED_SERVICES = [
            "unsupported_service"
        ]
        repokid.utils.roledata.IAM_ACCESS_ADVISOR_UNSUPPORTED_ACTIONS = [
            "supported_service:unsupported_action"
        ]

        hooks = {}

        permissions_dict = {
            "arn:aws:iam::123456789012:role/all_services_used": [
                "iam:AddRoleToInstanceProfile",
                "iam:AttachRolePolicy",
                "ec2:AllocateHosts",
                "ec2:AssociateAddress",
            ],
            "arn:aws:iam::123456789012:role/unused_ec2": [
                "iam:AddRoleToInstanceProfile",
                "iam:AttachRolePolicy",
                "ec2:AllocateHosts",
                "ec2:AssociateAddress",
                "unsupported_service:action",
                "supported_service:unsuported_action",
            ],
            "arn:aws:iam::123456789012:role/additional_unused_ec2": [
                "iam:AddRoleToInstanceProfile",
                "iam:AttachRolePolicy",
                "ec2:AllocateHosts",
                "ec2:AssociateAddress",
            ],
            "arn:aws:iam::123456789012:role/unused_iam": [
                "iam:AddRoleToInstanceProfile",
                "iam:AttachRolePolicy",
            ],
        }

        true_repoable_decision = repokid.utils.roledata.RepoablePermissionDecision()
        true_repoable_decision.repoable = True

        false_repoable_decision = repokid.utils.roledata.RepoablePermissionDecision()
        false_repoable_decision.repoable = False

        # The new hook should return a dict mapping role arn's to a json of their repoable permissions with decisions
        mock_call_hooks.return_value = {
            "arn:aws:iam::123456789012:role/all_services_used": {
                "potentially_repoable_permissions": {
                    "iam:AddRoleToInstanceProfile": false_repoable_decision,
                    "iam:AttachRolePolicy": false_repoable_decision,
                    "ec2:AllocateHosts": false_repoable_decision,
                    "ec2:AssociateAddress": false_repoable_decision,
                }
            },
            "arn:aws:iam::123456789012:role/unused_ec2": {
                "potentially_repoable_permissions": {
                    "iam:AddRoleToInstanceProfile": false_repoable_decision,
                    "iam:AttachRolePolicy": false_repoable_decision,
                    "ec2:AllocateHosts": true_repoable_decision,
                    "ec2:AssociateAddress": true_repoable_decision,
                }
            },
            "arn:aws:iam::123456789012:role/additional_unused_ec2": {
                "potentially_repoable_permissions": {
                    "iam:AddRoleToInstanceProfile": false_repoable_decision,
                    "iam:AttachRolePolicy": false_repoable_decision,
                    "ec2:AllocateHosts": false_repoable_decision,
                    "ec2:AssociateAddress": false_repoable_decision,
                    "unsupported_service:action": false_repoable_decision,
                    "supported_service:unsupported_action": false_repoable_decision,
                }
            },
            "arn:aws:iam::123456789012:role/unused_iam": {
                "potentially_repoable_permissions": {
                    "iam:AddRoleToInstanceProfile": true_repoable_decision,
                    "iam:AttachRolePolicy": true_repoable_decision,
                    "ec2:AllocateHosts": false_repoable_decision,
                    "ec2:AssociateAddress": false_repoable_decision,
                }
            },
        }

        repoable_permissions_dict = {
            "arn:aws:iam::123456789012:role/all_services_used": set(),
            "arn:aws:iam::123456789012:role/unused_ec2": {
                "ec2:AllocateHosts",
                "ec2:AssociateAddress",
            },
            "arn:aws:iam::123456789012:role/additional_unused_ec2": set(),
            "arn:aws:iam::123456789012:role/unused_iam": {
                "iam:AddRoleToInstanceProfile",
                "iam:AttachRolePolicy",
            },
        }

        assert (
            repoable_permissions_dict
            == repokid.utils.roledata._get_repoable_permissions_batch(
                roles, permissions_dict, minimum_age, hooks, 2
            )
        )
        assert (
            repoable_permissions_dict
            == repokid.utils.roledata._get_repoable_permissions_batch(
                roles, permissions_dict, minimum_age, hooks, 4
            )
        )

    @patch("repokid.utils.roledata._get_role_permissions")
    @patch("repokid.utils.roledata._get_repoable_permissions")
    @patch("repokid.hooks.call_hooks")
    def test_calculate_repo_scores(
        self, mock_call_hooks, mock_get_repoable_permissions, mock_get_role_permissions
    ):
        roles = [
            Role.parse_obj(ROLES[0]),
            Role.parse_obj(ROLES[1]),
            Role.parse_obj(ROLES[2]),
        ]
        roles[0].disqualified_by = []
        roles[0].aa_data = "some_aa_data"

        # disqualified by a filter
        roles[1].policies = [{"Policy": ROLE_POLICIES["unused_ec2"]}]
        roles[1].disqualified_by = ["some_filter"]
        roles[1].aa_data = "some_aa_data"

        # no AA data
        roles[2].policies = [{"Policy": ROLE_POLICIES["all_services_used"]}]
        roles[2].disqualified_by = []
        roles[2].aa_data = None

        hooks = {}

        mock_get_role_permissions.side_effect = [
            (
                [
                    "iam:AddRoleToInstanceProfile",
                    "iam:AttachRolePolicy",
                    "ec2:AllocateHosts",
                    "ec2:AssociateAddress",
                ],
                ["iam:AddRoleToInstanceProfile", "iam:AttachRolePolicy"],
            ),
            (
                ["iam:AddRoleToInstanceProfile", "iam:AttachRolePolicy"],
                ["iam:AddRoleToInstanceProfile", "iam:AttachRolePolicy"],
            ),
            (
                ["iam:AddRoleToInstanceProfile", "iam:AttachRolePolicy"],
                ["iam:AddRoleToInstanceProfile", "iam:AttachRolePolicy"],
            ),
        ]

        mock_call_hooks.return_value = {
            "iam:AddRoleToInstanceProfile",
            "iam:AttachRolePolicy",
        }
        mock_get_repoable_permissions.side_effect = [
            {"iam:AddRoleToInstanceProfile", "iam:AttachRolePolicy"}
        ]

        minimum_age = 90
        repokid.utils.roledata._calculate_repo_scores(roles, minimum_age, hooks)

        assert roles[0].repoable_permissions == 2
        assert roles[0].repoable_services == ["iam"]
        assert roles[1].repoable_permissions == 0
        assert roles[1].repoable_services == []
        assert roles[2].repoable_permissions == 0
        assert roles[2].repoable_services == []

    @patch("repokid.utils.roledata._get_role_permissions")
    @patch("repokid.utils.roledata._get_repoable_permissions_batch")
    @patch("repokid.hooks.call_hooks")
    def test_calculate_repo_scores_batch(
        self,
        mock_call_hooks,
        mock_get_repoable_permissions_batch,
        mock_get_role_permissions,
    ):
        roles = [
            Role.parse_obj(ROLES[0]),
            Role.parse_obj(ROLES[1]),
            Role.parse_obj(ROLES[2]),
            Role.parse_obj(ROLES[4]),
            Role.parse_obj(ROLES[5]),
        ]
        roles[0].disqualified_by = []
        roles[0].aa_data = "some_aa_data"

        # disqualified by a filter
        roles[1].policies = [{"Policy": ROLE_POLICIES["unused_ec2"]}]
        roles[1].disqualified_by = ["some_filter"]
        roles[1].aa_data = "some_aa_data"

        # no AA data
        roles[2].policies = [{"Policy": ROLE_POLICIES["all_services_used"]}]
        roles[2].disqualified_by = []
        roles[2].aa_data = None

        roles[3].disqualified_by = []
        roles[3].aa_data = "some_aa_data"

        roles[4].disqualified_by = []
        roles[4].aa_data = "some_aa_data"

        hooks = {}

        mock_get_role_permissions.side_effect = [
            (
                [
                    "iam:AddRoleToInstanceProfile",
                    "iam:AttachRolePolicy",
                    "ec2:AllocateHosts",
                    "ec2:AssociateAddress",
                ],
                ["iam:AddRoleToInstanceProfile", "iam:AttachRolePolicy"],
            ),
            (
                ["iam:AddRoleToInstanceProfile", "iam:AttachRolePolicy"],
                ["iam:AddRoleToInstanceProfile", "iam:AttachRolePolicy"],
            ),
            (
                ["iam:AddRoleToInstanceProfile", "iam:AttachRolePolicy"],
                ["iam:AddRoleToInstanceProfile", "iam:AttachRolePolicy"],
            ),
            (
                [
                    "iam:AddRoleToInstanceProfile",
                    "iam:AttachRolePolicy",
                    "ec2:AllocateHosts",
                    "ec2:AssociateAddress",
                ],
                ["ec2:AllocateHosts", "ec2:AssociateAddress"],
            ),
            (
                [
                    "iam:AddRoleToInstanceProfile",
                    "iam:AttachRolePolicy",
                    "ec2:AllocateHosts",
                    "ec2:AssociateAddress",
                ],
                ["iam:AddRoleToInstanceProfile", "iam:AttachRolePolicy"],
            ),
        ]

        mock_call_hooks.return_value = {
            "iam:AddRoleToInstanceProfile",
            "iam:AttachRolePolicy",
        }

        batch_perms_dict = {
            roles[0].arn: {"iam:AddRoleToInstanceProfile", "iam:AttachRolePolicy"},
            roles[3].arn: {"ec2:AllocateHosts", "ec2:AssociateAddress"},
            roles[4].arn: {"iam:AddRoleToInstanceProfile", "iam:AttachRolePolicy"},
        }

        mock_get_repoable_permissions_batch.side_effect = [batch_perms_dict]

        minimum_age = 90
        repokid.utils.roledata._calculate_repo_scores(
            roles, minimum_age, hooks, batch=True, batch_size=100
        )

        assert roles[0].repoable_permissions == 2
        assert roles[0].repoable_services == ["iam"]
        assert roles[1].repoable_permissions == 0
        assert roles[1].repoable_services == []
        assert roles[2].repoable_permissions == 0
        assert roles[2].repoable_services == []
        assert roles[3].repoable_permissions == 2
        assert roles[3].repoable_services == ["ec2"]
        assert roles[4].repoable_permissions == 2
        assert roles[4].repoable_services == ["iam"]

    def test_get_repoed_policy(self):
        policies = ROLE_POLICIES["all_services_used"]
        repoable_permissions = {
            "iam:addroletoinstanceprofile",
            "iam:attachrolepolicy",
            "s3:createbucket",
        }

        rewritten_policies, empty_policies = repokid.utils.roledata._get_repoed_policy(
            policies, repoable_permissions
        )

        assert rewritten_policies == {
            "s3_perms": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Action": ["s3:deletebucket"],
                        "Resource": ["*"],
                        "Effect": "Allow",
                    }
                ],
            }
        }
        assert empty_policies == ["iam_perms"]

    def test_find_newly_added_permissions(self):
        old_policy = ROLE_POLICIES["all_services_used"]
        new_policy = ROLE_POLICIES["unused_ec2"]

        new_perms = repokid.utils.roledata.find_newly_added_permissions(
            old_policy, new_policy
        )
        assert new_perms == {"ec2:allocatehosts", "ec2:associateaddress"}

    def test_convert_repoable_perms_to_perms_and_services(self):
        all_perms = {"a:j", "a:k", "b:l", "c:m", "c:n"}
        repoable_perms = {"b:l", "c:m"}
        expected_repoed_services = {"b"}
        expected_repoed_permissions = {"c:m"}
        assert repokid.utils.roledata._convert_repoable_perms_to_perms_and_services(
            all_perms, repoable_perms
        ) == (expected_repoed_permissions, expected_repoed_services)

    def test_convert_repoed_service_to_sorted_perms_and_services(self):
        repoed_services = {
            "route53",
            "ec2",
            "s3:abc",
            "dynamodb:def",
            "ses:ghi",
            "ses:jkl",
        }
        expected_services = ["ec2", "route53"]
        expected_permissions = ["dynamodb:def", "s3:abc", "ses:ghi", "ses:jkl"]
        assert (
            repokid.utils.roledata._convert_repoed_service_to_sorted_perms_and_services(
                repoed_services
            )
            == (
                expected_permissions,
                expected_services,
            )
        )

    def test_get_epoch_authenticated(self):
        assert repokid.utils.roledata._get_epoch_authenticated(1545787620000) == (
            1545787620,
            True,
        )
        assert repokid.utils.roledata._get_epoch_authenticated(1545787620) == (
            1545787620,
            True,
        )
        assert repokid.utils.roledata._get_epoch_authenticated(154578762) == (
            -1,
            False,
        )

    def test_filter_scheduled_repoable_perms(self):
        assert repokid.utils.roledata._filter_scheduled_repoable_perms(
            {"a:b", "a:c", "b:a"}, {"a:c", "b"}
        ) == ["a:c", "b:a"]
        assert repokid.utils.roledata._filter_scheduled_repoable_perms(
            {"a:b", "a:c", "b:a"}, {"a", "b"}
        ) == ["a:b", "a:c", "b:a"]
        assert repokid.utils.roledata._filter_scheduled_repoable_perms(
            {"a:b", "a:c", "b:a"}, {"a:b", "a:c"}
        ) == ["a:b", "a:c"]

    def test_get_repoed_policy_sid(self):
        """roledata._get_repoed_policy(policies, repoable_permissions)

        Cases to consider:

        Ensure statements with Sid's starting with STATEMENT_SKIP_SID are properly ignored.
        Ensure statements with no repoable permissions are not modified (expanded/inverted/etc)

        Other statements may be modified.
        """
        import json

        class TestPolicy:
            def __init__(self, sid=None, actions=None):
                self.sid = sid
                self.actions = actions

            def to_dict(self):
                policy = {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Action": self.actions, "Resource": ["*"], "Effect": "Allow"}
                    ],
                }

                if self.sid:
                    policy["Statement"][0]["Sid"] = self.sid
                return policy

        sid = "{}-jira1234".format(repokid.utils.roledata.STATEMENT_SKIP_SID)
        policies = {
            "norepo_sid": TestPolicy(
                sid=sid, actions=["s3:getobject", "iam:get*", "sqs:createqueue"]
            ).to_dict(),
            "norepo_used_permissions": TestPolicy(actions=["iam:get*"]).to_dict(),
            "repo_some": TestPolicy(
                actions=["iam:getaccesskeylastused", "sqs:createqueue"]
            ).to_dict(),
            "repo_all": TestPolicy(actions=["sqs:createqueue"]).to_dict(),
        }
        repoable_permissions = {"sqs:createqueue"}
        repoed_policies, empty_policies = repokid.utils.roledata._get_repoed_policy(
            policies, repoable_permissions
        )

        expected_repo_some = TestPolicy(actions=["iam:getaccesskeylastused"]).to_dict()
        assert ["repo_all"] == empty_policies
        assert json.dumps(repoed_policies["norepo_sid"]) == json.dumps(
            policies["norepo_sid"]
        )
        assert json.dumps(repoed_policies["norepo_used_permissions"]) == json.dumps(
            policies["norepo_used_permissions"]
        )
        assert json.dumps(repoed_policies["repo_some"]) == json.dumps(
            expected_repo_some
        )

    def test_get_permissions_in_policy_sid(self):
        """roledata._get_permissions_in_policy(policy_dict, warn_unkown_perms=False)

        returns total_permissions, eligible_permissions

        Cases to consider:

        Eligible Permissions:
            no sid
            sid exists, but doesn't begin with STATEMENT_SKIP_SID

        Not Eligible Permissions:
            sid beginning with STATEMENT_SKIP_SID

        Eligible should always be a subset of total
        """

        class TestPolicy:
            def __init__(self, sid=None, actions=None):
                self.sid = sid
                self.actions = actions

            def to_dict(self):
                policy = {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Action": self.actions, "Resource": ["*"], "Effect": "Allow"}
                    ],
                }

                if self.sid:
                    policy["Statement"][0]["Sid"] = self.sid
                return policy

        sid = "{}-jira1234".format(repokid.utils.roledata.STATEMENT_SKIP_SID)
        policies = {
            "no_sid": TestPolicy(actions=["ec2:getregions"]).to_dict(),
            "other_sid": TestPolicy(
                sid="jira-1234", actions=["sqs:createqueue"]
            ).to_dict(),
            "norepo_sid": TestPolicy(sid=sid, actions=["sns:createtopic"]).to_dict(),
        }

        total, eligible = repokid.utils.roledata.get_permissions_in_policy(policies)

        # eligible is a subset of total
        assert eligible < total
        assert "ec2:getregions" in eligible
        assert "sqs:createqueue" in eligible
        assert "sns:createtopic" not in eligible
