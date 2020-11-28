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
import json
import logging
from typing import Any
from typing import Dict
from typing import List

LOGGER = logging.getLogger("repokid")


def log_deleted_and_repoed_policies(
    deleted_policy_names: List[str],
    repoed_policies: Dict[str, Any],
    role_name: str,
    account_number: str,
) -> None:
    """Logs data on policies that would otherwise be modified or deleted if the commit flag were set.

    Args:
        deleted_policy_names (list<string>)
        repoed_policies (list<dict>)
        role_name (string)
        account_number (string)

    Returns:
        None
    """
    for name in deleted_policy_names:
        LOGGER.info(
            "Would delete policy from {} with name {} in account {}".format(
                role_name, name, account_number
            )
        )

    if repoed_policies:
        LOGGER.info(
            "Would replace policies for role {} with: \n{} in account {}".format(
                role_name,
                json.dumps(repoed_policies, indent=2, sort_keys=True),
                account_number,
            )
        )
