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

import botocore
from cloudaux import sts_conn
from cloudaux.aws.iam import (
    delete_role_policy,
    get_role_inline_policies,
    put_role_policy,
)
from repokid.utils import roledata as roledata
from repokid.utils.dynamo import set_role_data
from repokid.utils.logging import log_deleted_and_repoed_policies
from repokid.utils.roledata import partial_update_role_data

LOGGER = logging.getLogger("repokid")
MAX_AWS_POLICY_SIZE = 10240


@sts_conn("iam")
def update_repoed_description(role_name, client=None):
    description = None
    try:
        description = client.get_role(RoleName=role_name)["Role"].get("Description", "")
    except KeyError:
        return
    date_string = datetime.datetime.utcnow().strftime("%m/%d/%y")
    if "; Repokid repoed" in description:
        new_description = re.sub(
            r"; Repokid repoed [0-9]{2}\/[0-9]{2}\/[0-9]{2}",
            "; Repokid repoed {}".format(date_string),
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


def inline_policies_size_exceeds_maximum(policies):
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


def delete_policy(name, role, account_number, conn):
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
        return "Error deleting policy: {} from role: {} in account {}.  Exception: {}".format(
            name, role.role_name, account_number, e
        )


def replace_policies(repoed_policies, role, account_number, conn):
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
            error = "Exception calling PutRolePolicy on {role}/{policy} in account {account}\n{e}\n".format(
                role=role.role_name,
                policy=policy_name,
                account=account_number,
                e=str(e),
            )
            return error


def remove_permissions_from_role(
    account_number,
    permissions,
    role,
    role_id,
    dynamo_table,
    config,
    hooks,
    commit=False,
):
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
    repoed_policies, deleted_policy_names = roledata._get_repoed_policy(
        role.policies[-1]["Policy"], permissions
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
        error = delete_policy(name, role, account_number, conn)
        if error:
            LOGGER.error(error)

    if repoed_policies:
        error = replace_policies(repoed_policies, role, account_number, conn)
        if error:
            LOGGER.error(error)

    current_policies = get_role_inline_policies(role.as_dict(), **conn) or {}
    roledata.add_new_policy_version(dynamo_table, role, current_policies, "Repo")

    set_role_data(
        dynamo_table, role.role_id, {"Repoed": datetime.datetime.utcnow().isoformat()}
    )
    update_repoed_description(role.role_name, **conn)
    partial_update_role_data(
        role,
        dynamo_table,
        account_number,
        config,
        conn,
        hooks,
        source="ManualPermissionRepo",
        add_no_repo=False,
    )
    LOGGER.info(
        "Successfully removed {permissions} from role: {role} in account {account_number}".format(
            permissions=permissions, role=role.role_name, account_number=account_number
        )
    )
