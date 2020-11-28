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
from typing import Any
from typing import Dict

import requests

from repokid.exceptions import AardvarkError

LOGGER = logging.getLogger("repokid")


def get_aardvark_data(
    aardvark_api_location: str, account_number: str = "", arn: str = ""
) -> Dict[str, Any]:
    """
    Make a request to the Aardvark server to get all data about a given account or ARN.
    We'll request in groups of PAGE_SIZE and check the current count to see if we're done. Keep requesting as long as
    the total count (reported by the API) is greater than the number of pages we've received times the page size.  As
    we go, keeping building the dict and return it when done.

    Args:
        aardvark_api_location
        account_number (string): Used to form the phrase query for Aardvark so we only get data for the account we want
        arn (string)

    Returns:
        dict: Aardvark data is a dict with the role ARN as the key and a list of services as value
    """
    response_data = {}

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
            r_aardvark = requests.post(
                aardvark_api_location, params=params, json=payload
            )
        except requests.exceptions.RequestException as e:
            LOGGER.exception("Unable to get Aardvark data: {}".format(e))
            raise AardvarkError("Unable to get aardvark data")
        else:
            if r_aardvark.status_code != 200:
                LOGGER.exception("Unable to get Aardvark data")
                raise AardvarkError("Unable to get aardvark data")

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
