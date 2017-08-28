import json
import sys

import botocore
from cloudaux.aws.sts import boto3_cached_conn

from repokid.cli.repokid_cli import Filter
from repokid import LOGGER


def get_blacklist_from_bucket(bucket_config):
    try:
        s3_resource = boto3_cached_conn('s3', service_type='resource',
                                        account_number=bucket_config.get('account_number'),
                                        assume_role=bucket_config.get('assume_role', None),
                                        session_name='repokid',
                                        region=bucket_config.get('region', 'us-west-2'))

        s3_obj = s3_resource.Object(bucket_name=bucket_config['bucket_name'], key=bucket_config['key'])
        blacklist = s3_obj.get()['Body'].read().decode("utf-8")
        blacklist_json = json.loads(blacklist)
    # Blacklist problems are really bad and we should quit rather than silently continue
    except (botocore.exceptions.ClientError, AttributeError):
        LOGGER.error("S3 blacklist config was set but unable to connect retrieve object, quitting")
        sys.exit(1)
    except ValueError:
        LOGGER.error("S3 blacklist config was set but the returned file is bad, quitting")
        sys.exit(1)
    if set(blacklist_json.keys()) != set(['arns', 'names']):
        LOGGER.error("S3 blacklist file is malformed, quitting")
        sys.exit(1)
    return blacklist_json


class BlacklistFilter(Filter):
    def __init__(self, config=None):
        blacklist_json = None
        bucket_config = config.get('blacklist_bucket', None)
        if bucket_config:
            blacklist_json = get_blacklist_from_bucket(bucket_config)

        current_account = config.get('current_account') or None
        if not current_account:
            LOGGER.error('Unable to get current account for Blacklist Filter')

        blacklisted_role_names = set()
        blacklisted_role_names.update([rolename.lower() for rolename in config.get(current_account, [])])
        blacklisted_role_names.update([rolename.lower() for rolename in config.get('all', [])])

        if blacklist_json:
            blacklisted_role_names.update([name.lower() for name, accounts in blacklist_json['names'].items() if
                                          ('all' in accounts or config.get('current_account') in accounts)])

        self.blacklisted_arns = set() if not blacklist_json else blacklist_json.get('arns', [])
        self.blacklisted_role_names = blacklisted_role_names

    def apply(self, input_list):
        blacklisted_roles = []

        for role in input_list:
            if(role.role_name.lower() in self.blacklisted_role_names or role.arn in self.blacklisted_arns):
                blacklisted_roles.append(role)
        return blacklisted_roles
