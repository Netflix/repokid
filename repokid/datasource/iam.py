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
from typing import Dict
from typing import Iterable
from typing import Optional

from cloudaux.aws.iam import get_account_authorization_details
from cloudaux.orchestration.aws.iam.role import FLAGS
from cloudaux.orchestration.aws.iam.role import get_role

from repokid.datasource.plugin import DatasourcePlugin
from repokid.exceptions import NotFoundError
from repokid.plugin import Singleton
from repokid.types import IAMEntry
from repokid.types import RepokidConfig

logger = logging.getLogger("repokid")


class IAMDatasource(DatasourcePlugin[str, IAMEntry], metaclass=Singleton):
    _arn_to_id: Dict[str, str] = {}

    def __init__(self, config: Optional[RepokidConfig] = None):
        super().__init__(config=config)

    def _fetch_account(self, account_number: str) -> Dict[str, IAMEntry]:
        logger.info("getting role data for account %s", account_number)
        conn = copy.deepcopy(self.config.get("connection_iam", {}))
        conn["account_number"] = account_number
        auth_details = get_account_authorization_details(filter="Role", **conn)
        auth_details_by_id = {item["Arn"]: item for item in auth_details}
        self._arn_to_id.update({item["Arn"]: item["RoleId"] for item in auth_details})
        # convert policies list to dictionary to maintain consistency with old call which returned a dict
        for _, data in auth_details_by_id.items():
            data["RolePolicyList"] = {
                item["PolicyName"]: item["PolicyDocument"]
                for item in data["RolePolicyList"]
            }
        return auth_details_by_id

    def _fetch(self, arn: str) -> IAMEntry:
        logger.info("getting role data for role %s", arn)
        conn = copy.deepcopy(self.config["connection_iam"])
        conn["account_number"] = arn.split(":")[4]
        role = {"RoleName": arn.split("/")[-1]}
        role_info: IAMEntry = get_role(role, flags=FLAGS.INLINE_POLICIES, **conn)
        self._arn_to_id[arn] = role_info["RoleId"]
        if not role_info:
            raise NotFoundError
        self._data[arn] = role_info
        return role_info

    def get(self, arn: str) -> IAMEntry:
        result = self._data.get(arn)
        if not result:
            return self._fetch(arn)
        return result

    def get_id_for_arn(self, arn: str) -> Optional[str]:
        return self._arn_to_id.get(arn)

    def _get_ids_for_account(self, account_number: str) -> Iterable[str]:
        ids_for_account = [
            k for k, v in self.items() if v["Arn"].split(":")[4] == account_number
        ]
        return ids_for_account

    def seed(self, account_number: str) -> Iterable[str]:
        if account_number in self._seeded:
            return self._get_ids_for_account(account_number)
        fetched_data = self._fetch_account(account_number)
        new_keys = fetched_data.keys()
        self._data.update(fetched_data)
        self._seeded.append(account_number)
        return new_keys


# TODO: Implement retrieval of IAM data from AWS Config
class ConfigDatasource(DatasourcePlugin[str, IAMEntry], metaclass=Singleton):
    def __init__(self, config: Optional[RepokidConfig] = None):
        super().__init__(config=config)

    def get(self, identifier: str) -> IAMEntry:
        pass

    def seed(self, identifier: str) -> Iterable[str]:
        pass
