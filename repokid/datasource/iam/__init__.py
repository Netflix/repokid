#  Copyright 2021 Netflix, Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import copy
import logging
from typing import Any
from typing import Dict
from typing import Optional

from cloudaux.aws.iam import get_account_authorization_details

from repokid.datasource import DatasourcePlugin
from repokid.exceptions import NotFoundError
from repokid.plugin import Singleton
from repokid.types import RepokidConfig

logger = logging.getLogger("repokid")


class IAMDatasource(DatasourcePlugin[Dict[str, Any]], Singleton):
    def __init__(self, config: Optional[RepokidConfig] = None):
        super().__init__(config=config)

    def get(self, identifier: str) -> Dict[str, Any]:
        result = self._data.get(identifier)
        if not result:
            raise NotFoundError
        return result

    def seed(self, identifier: str) -> None:
        logger.info("getting role data for account %s", identifier)
        conn = copy.deepcopy(self.config["connection_iam"])
        conn["account_number"] = identifier
        auth_details = get_account_authorization_details(filter="Role", **conn)
        auth_details_by_id = {item["RoleId"]: item for item in auth_details}
        # convert policies list to dictionary to maintain consistency with old call which returned a dict
        for _, data in auth_details_by_id.items():
            data["RolePolicyList"] = {
                item["PolicyName"]: item["PolicyDocument"]
                for item in data["RolePolicyList"]
            }
        self._data.update(auth_details_by_id)


class ConfigDatasource(DatasourcePlugin[Dict[str, Any]], Singleton):
    def __init__(self, config: Optional[RepokidConfig] = None):
        super().__init__(config=config)

    def get(self, identifier: str) -> Dict[str, Any]:
        pass

    def seed(self, identifier: str) -> None:
        pass
