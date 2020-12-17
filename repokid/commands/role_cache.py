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
import logging

from cloudaux.aws.iam import get_account_authorization_details
from mypy_boto3_dynamodb.service_resource import Table
from tqdm import tqdm

from repokid.filters.utils import get_filter_plugins
from repokid.role import Role
from repokid.role import RoleList
from repokid.types import RepokidConfig
from repokid.types import RepokidHooks

LOGGER = logging.getLogger("repokid")


def _update_role_cache(
    account_number: str,
    dynamo_table: Table,
    config: RepokidConfig,
    hooks: RepokidHooks,
) -> None:
    """
    Update data about all roles in a given account:
      1) list all the roles and initiate a role object with basic data including name and roleID
      2) get inline policies for each of the roles
      3) build a list of active roles - we'll want to keep data about roles that may have been deleted in case we
         need to restore them, so if we used to have a role and now we don't see it we'll mark it inactive
      4) update data about the roles in Dynamo
      5) mark inactive roles in Dynamo
      6) load and instantiate filter plugins
      7) for each filter determine the list of roles that it filters
      8) update data in Dynamo about filters
      9) get Aardvark data for each role
      10) update Dynamo with Aardvark data
      11) calculate repoable permissions/policies for all the roles
      12) update Dynamo with information about how many total and repoable permissions and which services are repoable
      13) update stats in Dynamo with basic information like total permissions and which filters are applicable

    Args:
        account_number (string): The current account number Repokid is being run against

    Returns:
        None
    """
    conn = config["connection_iam"]
    conn["account_number"] = account_number

    LOGGER.info(
        "Getting current role data for account {} (this may take a while for large accounts)".format(
            account_number
        )
    )

    role_data = get_account_authorization_details(filter="Role", **conn)
    role_data_by_id = {item["RoleId"]: item for item in role_data}

    # convert policies list to dictionary to maintain consistency with old call which returned a dict
    for _, data in role_data_by_id.items():
        data["RolePolicyList"] = {
            item["PolicyName"]: item["PolicyDocument"]
            for item in data["RolePolicyList"]
        }

    roles = RoleList([Role(**rd) for rd in role_data])

    LOGGER.info("Updating role data for account {}".format(account_number))
    for role in tqdm(roles):
        role.account = account_number
        current_policies = role_data_by_id[role.role_id]["RolePolicyList"]
        role.gather_role_data(
            current_policies, hooks, config, source="Scan", store=False
        )

    LOGGER.info("Finding inactive roles in account {}".format(account_number))
    # roledata.find_and_mark_inactive(dynamo_table, account_number, roles)

    LOGGER.info("Filtering roles")
    plugins = get_filter_plugins(account_number)
    for plugin in plugins.filter_plugins:
        filtered_list = plugin.apply(roles)
        class_name = plugin.__class__.__name__
        for filtered_role in filtered_list:
            LOGGER.debug(
                "Role {} filtered by {}".format(filtered_role.role_name, class_name)
            )
            filtered_role.disqualified_by.append(class_name)

    for role in roles:
        LOGGER.debug(
            "Role {} in account {} has\nrepoable permissions: {}\nrepoable services: {}".format(
                role.role_name,
                account_number,
                role.repoable_permissions,
                role.repoable_services,
            )
        )

    LOGGER.info("Storing updated role data in account {}".format(account_number))
    roles.store()
