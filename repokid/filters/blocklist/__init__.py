import json
import sys

import botocore
from cloudaux.aws.sts import boto3_cached_conn
from repokid import LOGGER
from repokid.cli.repokid_cli import Filter


def get_blocklist_from_bucket(bucket_config):
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
        LOGGER.error(
            "S3 blocklist config was set but unable to connect retrieve object, quitting"
        )
        sys.exit(1)
    except ValueError:
        LOGGER.error(
            "S3 blocklist config was set but the returned file is bad, quitting"
        )
        sys.exit(1)
    if set(blocklist_json.keys()) != set(["arns", "names"]):
        LOGGER.error("S3 blocklist file is malformed, quitting")
        sys.exit(1)
    return blocklist_json


class BlocklistFilter(Filter):
    def __init__(self, config=None):
        blocklist_json = None
        bucket_config = config.get(
            "blocklist_bucket", config.get("blacklist_bucket", None)
        )
        if bucket_config:
            blocklist_json = get_blocklist_from_bucket(bucket_config)

        current_account = config.get("current_account") or None
        if not current_account:
            LOGGER.error("Unable to get current account for Blocklist Filter")

        blocklisted_role_names = set()
        blocklisted_role_names.update(
            [rolename.lower() for rolename in config.get(current_account, [])]
        )
        blocklisted_role_names.update(
            [rolename.lower() for rolename in config.get("all", [])]
        )

        if blocklist_json:
            blocklisted_role_names.update(
                [
                    name.lower()
                    for name, accounts in blocklist_json["names"].items()
                    if ("all" in accounts or config.get("current_account") in accounts)
                ]
            )

        self.blocklisted_arns = (
            set() if not blocklist_json else blocklist_json.get("arns", [])
        )
        self.blocklisted_role_names = blocklisted_role_names

    def apply(self, input_list):
        blocklisted_roles = []

        for role in input_list:
            if (
                role.role_name.lower() in self.blocklisted_role_names
                or role.arn in self.blocklisted_arns
            ):
                blocklisted_roles.append(role)
        return blocklisted_roles
