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
import json
import logging
import re
from typing import Any
from typing import Dict
from typing import List

import botocore
from cloudaux.aws.iam import delete_role_policy
from cloudaux.aws.iam import get_role_inline_policies
from cloudaux.aws.iam import put_role_policy
from cloudaux.aws.sts import boto3_cached_conn
from mypy_boto3_iam.client import IAMClient

import repokid.utils.permissions
from repokid.exceptions import IAMError
from repokid.role import Role
from repokid.types import RepokidConfig
from repokid.types import RepokidHooks
from repokid.utils.logging import log_deleted_and_repoed_policies

LOGGER = logging.getLogger("repokid")
MAX_AWS_POLICY_SIZE = 10240


def update_repoed_description(role_name: str, conn_details: Dict[str, Any]) -> None:
    client: IAMClient = boto3_cached_conn("iam", **conn_details)
    try:
        description = client.get_role(RoleName=role_name)["Role"].get("Description", "")
    except KeyError:
        return
    date_string = datetime.datetime.now(tz=datetime.timezone.utc).strftime("%m/%d/%y")
    if "; Repokid repoed" in description:
        new_description = re.sub(
            r"; Repokid repoed [0-9]{2}\/[0-9]{2}\/[0-9]{2}",
            f"; Repokid repoed {date_string}",
            description,
        )
    else:
        new_description = description + " ; Repokid repoed {}".format(date_string)
    # IAM role descriptions have a max length of 1000, if our new length would be longer, skip this
    if len(new_description) < 1000:
        client.update_role_description(RoleName=role_name, Description=new_description)
    else:
        LOGGER.error(
            "Unable to set repo description ({}) for role {}, length would be too long".format(
                new_description, role_name
            )
        )


def inline_policies_size_exceeds_maximum(policies: Dict[str, Any]) -> bool:
    """Validate the policies, when converted to JSON without whitespace, remain under the size limit.

    Args:
        policies (list<dict>)
    Returns:
        bool
    """
    exported_no_whitespace = json.dumps(policies, separators=(",", ":"))
    if len(exported_no_whitespace) > MAX_AWS_POLICY_SIZE:
        return True
    return False


def delete_policy(
    name: str, role: Role, account_number: str, conn: Dict[str, Any]
) -> None:
    """Deletes the specified IAM Role inline policy.

    Args:
        name (string)
        role (Role object)
        account_number (string)
        conn (dict)

    Returns:
        error (string) or None
    """
    LOGGER.info(
        "Deleting policy with name {} from {} in account {}".format(
            name, role.role_name, account_number
        )
    )
    try:
        delete_role_policy(RoleName=role.role_name, PolicyName=name, **conn)
    except botocore.exceptions.ClientError as e:
        raise IAMError(
            f"Error deleting policy: {name} from role: {role.role_name} in account {account_number}"
        ) from e


def replace_policies(
    repoed_policies: Dict[str, Any],
    role: Role,
    account_number: str,
    conn: Dict[str, Any],
) -> None:
    """Overwrite IAM Role inline policies with those supplied.

    Args:
        repoed_policies (dict)
        role (Role object)
        account_number (string)
        conn (dict)

    Returns:
        error (string) or None
    """
    LOGGER.info(
        "Replacing Policies With: \n{} (role: {} account: {})".format(
            json.dumps(repoed_policies, indent=2, sort_keys=True),
            role.role_name,
            account_number,
        )
    )

    for policy_name, policy in repoed_policies.items():
        try:
            put_role_policy(
                RoleName=role.role_name,
                PolicyName=policy_name,
                PolicyDocument=json.dumps(policy, indent=2, sort_keys=True),
                **conn,
            )

        except botocore.exceptions.ClientError as e:
            error = "Exception calling PutRolePolicy on {role}/{policy} in account {account}".format(
                role=role.role_name,
                policy=policy_name,
                account=account_number,
            )
            raise IAMError(error) from e


def remove_permissions_from_role(
    account_number: str,
    permissions: List[str],
    role: Role,
    config: RepokidConfig,
    hooks: RepokidHooks,
    commit: bool = False,
) -> None:
    """Remove the list of permissions from the provided role.

    Args:
        account_number (string)
        permissions (list<string>)
        role (Role object)
        role_id (string)
        commit (bool)

    Returns:
        None
    """
    (
        repoed_policies,
        deleted_policy_names,
    ) = repokid.utils.permissions.get_repoed_policy(
        role.policies[-1]["Policy"], set(permissions)
    )

    if inline_policies_size_exceeds_maximum(repoed_policies):
        LOGGER.error(
            "Policies would exceed the AWS size limit after repo for role: {} in account {}.  "
            "Please manually minify.".format(role.role_name, account_number)
        )
        return

    if not commit:
        log_deleted_and_repoed_policies(
            deleted_policy_names, repoed_policies, role.role_name, account_number
        )
        return

    conn = config["connection_iam"]
    conn["account_number"] = account_number

    for name in deleted_policy_names:
        try:
            delete_policy(name, role, account_number, conn)
        except IAMError as e:
            LOGGER.error(e)

    if repoed_policies:
        try:
            replace_policies(repoed_policies, role, account_number, conn)
        except IAMError as e:
            LOGGER.error(e)

    current_policies = get_role_inline_policies(role.dict(), **conn) or {}
    role.add_policy_version(current_policies, "Repo")

    role.repoed = datetime.datetime.now(tz=datetime.timezone.utc).isoformat()
    update_repoed_description(role.role_name, conn)
    role.gather_role_data(
        current_policies, hooks, source="ManualPermissionRepo", add_no_repo=False
    )
    LOGGER.info(
        "Successfully removed {permissions} from role: {role} in account {account_number}".format(
            permissions=permissions, role=role.role_name, account_number=account_number
        )
    )
