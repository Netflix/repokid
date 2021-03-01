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

import logging
from typing import Any
from typing import Dict
from typing import Iterable
from typing import Optional

import requests

from repokid.datasource.plugin import DatasourcePlugin
from repokid.exceptions import AardvarkError
from repokid.exceptions import NotFoundError
from repokid.plugin import Singleton
from repokid.types import AardvarkResponse
from repokid.types import AccessAdvisorEntry
from repokid.types import RepokidConfig

logger = logging.getLogger("repokid")


class AccessAdvisorDatasource(
    DatasourcePlugin[str, AccessAdvisorEntry], metaclass=Singleton
):
    def __init__(self, config: Optional[RepokidConfig] = None):
        super().__init__(config=config)

    def _fetch(
        self, account_number: str = "", arn: str = ""
    ) -> Dict[str, AccessAdvisorEntry]:
        """
        Make a request to the Aardvark server to get all data about a given account or ARN.
        We'll request in groups of PAGE_SIZE and check the current count to see if we're done. Keep requesting as long
        as the total count (reported by the API) is greater than the number of pages we've received times the page size.
        As we go, keeping building the dict and return it when done.

        Args:
            account_number (string): Used to form the phrase query for Aardvark
            arn (string)

        Returns:
            dict: Aardvark data is a dict with the role ARN as the key and a list of services as value
        """
        api_location = self.config.get("aardvark_api_location")
        if not api_location:
            raise AardvarkError("aardvark not configured")

        response_data: AardvarkResponse = {}

        PAGE_SIZE = 1000
        page_num = 1

        payload: Dict[str, Any]
        if account_number:
            payload = {"phrase": account_number}
        elif arn:
            payload = {"arn": [arn]}
        else:
            return {}
        while True:
            params = {"count": PAGE_SIZE, "page": page_num}
            try:
                r_aardvark = requests.post(api_location, params=params, json=payload)
            except requests.exceptions.RequestException as e:
                logger.exception("unable to get Aardvark data: {}".format(e))
                raise AardvarkError("unable to get aardvark data")
            else:
                if r_aardvark.status_code != 200:
                    logger.exception("unable to get Aardvark data")
                    raise AardvarkError("unable to get aardvark data")

                response_data.update(r_aardvark.json())
                # don't want these in our Aardvark data
                response_data.pop("count")
                response_data.pop("page")
                response_data.pop("total")
                if PAGE_SIZE * page_num < r_aardvark.json().get("total"):
                    page_num += 1
                else:
                    break
        return response_data

    def get(self, arn: str) -> AccessAdvisorEntry:
        result = self._data.get(arn)
        if result:
            return result

        # Try to get data from Aardvark
        result = self._fetch(arn=arn).get(arn)
        if result:
            self._data[arn] = result
            return result
        raise NotFoundError

    def _get_arns_for_account(self, account_number: str) -> Iterable[str]:
        return filter(lambda x: x.split(":")[4] == account_number, self.keys())

    def seed(self, account_number: str) -> Iterable[str]:
        if account_number not in self._seeded:
            aa_data = self._fetch(account_number=account_number)
            self._data.update(aa_data)
            self._seeded.append(account_number)
            return aa_data.keys()
        else:
            return self._get_arns_for_account(account_number)
