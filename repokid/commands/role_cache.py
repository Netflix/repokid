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

from repokid.filters import FilterPlugins
from repokid.role import Role
from repokid.role import RoleList
from repokid.types import RepokidConfig
from repokid.types import RepokidHooks
from repokid.utils import roledata as roledata
from repokid.utils.aardvark import get_aardvark_data
from repokid.utils.dynamo import set_role_data

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

    roles = RoleList([Role.parse_obj(rd) for rd in role_data])

    active_roles = RoleList([])
    updated_roles = RoleList([])
    LOGGER.info("Updating role data for account {}".format(account_number))
    for role in tqdm(roles):
        role.account = account_number
        current_policies = role_data_by_id[role.role_id]["RolePolicyList"]
        active_roles.append(role)
        role = roledata.update_role_data(
            dynamo_table, account_number, role, current_policies
        )
        updated_roles.append(role)

    # Replace roles list with mutated Role objects
    roles = updated_roles

    LOGGER.info("Finding inactive roles in account {}".format(account_number))
    roledata.find_and_mark_inactive(dynamo_table, account_number, active_roles)

    LOGGER.info("Filtering roles")
    plugins = FilterPlugins()

    # Blocklist needs to know the current account
    filter_config = config["filter_config"]
    blocklist_filter_config = filter_config.get(
        "BlocklistFilter", filter_config.get("BlacklistFilter")
    )
    blocklist_filter_config["current_account"] = account_number

    for plugin_path in config.get("active_filters", []):
        plugin_name = plugin_path.split(":")[1]
        if plugin_name == "ExclusiveFilter":
            # ExclusiveFilter plugin active; try loading its config. Also, it requires the current account, so add it.
            exclusive_filter_config = filter_config.get("ExclusiveFilter", {})
            exclusive_filter_config["current_account"] = account_number
        plugins.load_plugin(
            plugin_path, config=config["filter_config"].get(plugin_name, None)
        )

    for plugin in plugins.filter_plugins:
        filtered_list = plugin.apply(roles)
        class_name = plugin.__class__.__name__
        for filtered_role in filtered_list:
            LOGGER.debug(
                "Role {} filtered by {}".format(filtered_role.role_name, class_name)
            )
            filtered_role.disqualified_by.append(class_name)

    for role in roles:
        set_role_data(
            dynamo_table, role.role_id, {"DisqualifiedBy": role.disqualified_by}
        )

    LOGGER.info("Getting data from Aardvark for account {}".format(account_number))
    aardvark_data = get_aardvark_data(
        config["aardvark_api_location"], account_number=account_number
    )

    LOGGER.info(
        "Updating roles with Aardvark data in account {}".format(account_number)
    )
    for role in roles:
        try:
            role.aa_data = aardvark_data[role.arn]
        except KeyError:
            LOGGER.warning(
                "Aardvark data not found for role: {} ({})".format(
                    role.role_id, role.role_name
                )
            )
        else:
            set_role_data(dynamo_table, role.role_id, {"AAData": role.aa_data})

    LOGGER.info(
        "Calculating repoable permissions and services for account {}".format(
            account_number
        )
    )

    batch_processing = config.get("query_role_data_in_batch", False)
    batch_size = config.get("batch_processing_size", 100)
    roledata._calculate_repo_scores(
        roles,
        config["filter_config"]["AgeFilter"]["minimum_age"],
        hooks,
        batch_processing,
        batch_size,
    )
    for role in roles:
        LOGGER.debug(
            "Role {} in account {} has\nrepoable permissions: {}\nrepoable services: {}".format(
                role.role_name,
                account_number,
                role.repoable_permissions,
                role.repoable_services,
            )
        )
        set_role_data(
            dynamo_table,
            role.role_id,
            {
                "TotalPermissions": role.total_permissions,
                "RepoablePermissions": role.repoable_permissions,
                "RepoableServices": role.repoable_services,
            },
        )

    LOGGER.info("Updating stats in account {}".format(account_number))
    roledata.update_stats(dynamo_table, roles, source="Scan")
