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
import repokid.utils.permissions
import repokid.utils.roledata
from tests.test_commands import ROLE_POLICIES

# AARDVARK_DATA maintained in test_repokid_cli


class TestRoledata(object):
    def test_get_repoed_policy(self):
        policies = ROLE_POLICIES["all_services_used"]
        repoable_permissions = {
            "iam:addroletoinstanceprofile",
            "iam:attachrolepolicy",
            "s3:createbucket",
        }

        (
            rewritten_policies,
            empty_policies,
        ) = repokid.utils.permissions.get_repoed_policy(policies, repoable_permissions)

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

        new_perms = repokid.utils.permissions.find_newly_added_permissions(
            old_policy, new_policy
        )
        assert new_perms == {"ec2:allocatehosts", "ec2:associateaddress"}

    def test_convert_repoable_perms_to_perms_and_services(self):
        all_perms = {"a:j", "a:k", "b:l", "c:m", "c:n"}
        repoable_perms = {"b:l", "c:m"}
        expected_repoed_services = {"b"}
        expected_repoed_permissions = {"c:m"}
        assert repokid.utils.permissions.convert_repoable_perms_to_perms_and_services(
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
        assert repokid.utils.permissions._get_epoch_authenticated(1545787620000) == (
            1545787620,
            True,
        )
        assert repokid.utils.permissions._get_epoch_authenticated(1545787620) == (
            1545787620,
            True,
        )
        assert repokid.utils.permissions._get_epoch_authenticated(154578762) == (
            -1,
            False,
        )
