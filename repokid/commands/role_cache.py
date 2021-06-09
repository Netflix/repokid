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

from tqdm import tqdm

from repokid.datasource.access_advisor import AccessAdvisorDatasource
from repokid.datasource.iam import IAMDatasource
from repokid.filters.utils import get_filter_plugins
from repokid.role import RoleList
from repokid.types import RepokidConfig
from repokid.types import RepokidHooks
from repokid.utils.roledata import find_and_mark_inactive

LOGGER = logging.getLogger("repokid")


def _update_role_cache(
    account_number: str,
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
    access_advisor_datasource = AccessAdvisorDatasource()
    access_advisor_datasource.seed(account_number)
    iam_datasource = IAMDatasource()
    role_arns = iam_datasource.seed(account_number)

    # We only iterate over the newly-seeded data (`role_arns`) so we don't duplicate work for runs on multiple accounts
    roles = RoleList.from_arns(role_arns)

    LOGGER.info("Updating role data for account {}".format(account_number))
    for role in tqdm(roles):
        role.account = account_number
        role.gather_role_data(hooks, config=config, source="Scan", store=False)
        # Reseting previous filters
        role.disqualified_by = list()

    LOGGER.info("Finding inactive roles in account {}".format(account_number))
    find_and_mark_inactive(account_number, roles)

    LOGGER.info("Filtering roles")
    plugins = get_filter_plugins(account_number, config=config)
    for plugin in plugins.filter_plugins:
        filtered_list = plugin.apply(roles)
        class_name = plugin.__class__.__name__
        for filtered_role in filtered_list:
            LOGGER.debug(
                "Role {} filtered by {}".format(filtered_role.role_name, class_name)
            )
            # There may be existing duplicate records, so we do a dance here to dedupe them.
            disqualified_by = set(filtered_role.disqualified_by)
            disqualified_by.add(class_name)
            filtered_role.disqualified_by = list(disqualified_by)

    for role in roles:
        role.calculate_repo_scores(
            config["filter_config"]["AgeFilter"]["minimum_age"], hooks
        )
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
