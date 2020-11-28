import json
import logging
from typing import Any
from typing import Dict
from typing import Set

import botocore
from cloudaux.aws.sts import boto3_cached_conn

from repokid.exceptions import BlocklistError
from repokid.filters import Filter
from repokid.role import RoleList
from repokid.types import RepokidFilterConfig

LOGGER = logging.getLogger("repokid")


def get_blocklist_from_bucket(bucket_config: Dict[str, Any]) -> Dict[str, Any]:
    blocklist_json: Dict[str, Any]
    try:
        s3_resource = boto3_cached_conn(
            "s3",
            service_type="resource",
            account_number=bucket_config.get("account_number"),
            assume_role=bucket_config.get("assume_role", None),
            session_name="repokid",
            region=bucket_config.get("region", "us-west-2"),
        )

        s3_obj = s3_resource.Object(
            bucket_name=bucket_config["bucket_name"], key=bucket_config["key"]
        )
        blocklist = s3_obj.get()["Body"].read().decode("utf-8")
        blocklist_json = json.loads(blocklist)
    # Blocklist problems are really bad and we should quit rather than silently continue
    except (botocore.exceptions.ClientError, AttributeError):
        LOGGER.critical(
            "S3 blocklist config was set but unable to connect retrieve object, quitting"
        )
        raise BlocklistError("Could not retrieve blocklist")
    except ValueError:
        LOGGER.critical(
            "S3 blocklist config was set but the returned file is bad, quitting"
        )
        raise BlocklistError("Could not parse blocklist")
    if set(blocklist_json.keys()) != {"arns", "names"}:
        LOGGER.critical("S3 blocklist file is malformed, quitting")
        raise BlocklistError("Could not parse blocklist")
    return blocklist_json


class BlocklistFilter(Filter):
    blocklist_json: Dict[str, Any] = {}

    def __init__(self, config: RepokidFilterConfig = None) -> None:
        super().__init__(config=config)
        if not config:
            LOGGER.error(
                "No configuration provided, cannot initialize Blocklist Filter"
            )
            return
        current_account = config.get("current_account") or ""
        if not current_account:
            LOGGER.error("Unable to get current account for Blocklist Filter")

        blocklisted_role_names = set()
        blocklisted_role_names.update(
            [rolename.lower() for rolename in config.get(current_account, [])]
        )
        blocklisted_role_names.update(
            [rolename.lower() for rolename in config.get("all", [])]
        )

        if BlocklistFilter.blocklist_json:
            blocklisted_role_names.update(
                [
                    name.lower()
                    for name, accounts in BlocklistFilter.blocklist_json[
                        "names"
                    ].items()
                    if ("all" in accounts or config.get("current_account") in accounts)
                ]
            )

        self.blocklisted_arns: Set[str] = (
            set()
            if not BlocklistFilter.blocklist_json
            else set(BlocklistFilter.blocklist_json.get("arns", []))
        )
        self.blocklisted_role_names = blocklisted_role_names

    @classmethod
    def init_blocklist(cls, config: RepokidFilterConfig) -> None:
        if not config:
            LOGGER.error("No config provided for blocklist filter")
            raise BlocklistError("No config provided for blocklist filter")
        if not cls.blocklist_json:
            bucket_config = config.get(
                "blocklist_bucket", config.get("blacklist_bucket", {})
            )
            if bucket_config:
                cls.blocklist_json = get_blocklist_from_bucket(bucket_config)

    def apply(self, input_list: RoleList) -> RoleList:
        blocklisted_roles = RoleList([])

        for role in input_list:
            if (
                role.role_name.lower() in self.blocklisted_role_names
                or role.arn in self.blocklisted_arns
            ):
                blocklisted_roles.append(role)
        return blocklisted_roles
