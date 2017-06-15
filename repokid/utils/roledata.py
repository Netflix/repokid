from datetime import datetime
import sys

import boto3
from botocore.exceptions import ClientError as BotoClientError
from cloudaux.aws.sts import boto3_cached_conn
from tqdm import tqdm

# used as a placeholder for empty SID to work around this: https://github.com/aws/aws-sdk-js/issues/833
DYNAMO_EMPTY_STRING = "---DYNAMO-EMPTY-STRING---"
DYNAMO_TABLE = None


def dynamo_get_or_create_table(**dynamo_config):
    """Create a new table or get a reference to the existing table"""
    global DYNAMO_TABLE

    if 'localhost' in dynamo_config['endpoint']:
        resource = boto3.resource('dynamodb',
            region_name='us-east-1',
            endpoint_url=dynamo_config['endpoint'])
    else:
        resource = boto3_cached_conn(
            'dynamodb',
            service_type='resource',
            account_number=dynamo_config['account_number'],
            assume_role=dynamo_config.get('assume_role', None),
            session_name=dynamo_config['session_name'],
            region=dynamo_config['region'])

    try:
        table = resource.create_table(
            TableName='repokid_roles',
            KeySchema=[{
                'AttributeName': 'RoleId',
                'KeyType': 'HASH'  # Partition key
            }],
            AttributeDefinitions=[{
                'AttributeName': 'RoleId',
                'AttributeType': 'S'
            }],
            ProvisionedThroughput={
                'ReadCapacityUnits': 5,
                'WriteCapacityUnits': 5
            })

        table.meta.client.get_waiter('table_exists').wait(TableName='repokid_roles')

        # need a global secondary index to list all role IDs for a given account number
        table.update(
            AttributeDefinitions=[{
                'AttributeName': 'Account',
                'AttributeType': 'S'
             }],
             GlobalSecondaryIndexUpdates=[{
                'Create': {
                    'IndexName': 'Account',
                    'KeySchema': [{
                        'AttributeName': 'Account',
                        'KeyType': 'HASH'
                    }],
                    'Projection': {
                        'NonKeyAttributes': ['RoleId'],
                        'ProjectionType': 'INCLUDE'
                    },
                    'ProvisionedThroughput': {
                        'ReadCapacityUnits': 2,
                        'WriteCapacityUnits': 2
                    }
                }}])

    except BotoClientError as e:
        if "ResourceInUseException" in e.message:
            table = resource.Table('repokid_roles')
        else:
            from repokid.repokid import LOGGER
            LOGGER.error(e)
            sys.exit(1)
    DYNAMO_TABLE = table


def update_repoable_data(roles):
    """Update total permissions, repoable permissions, and repoable services for an account"""
    for role in roles:
        try:
            DYNAMO_TABLE.update_item(Key={'RoleId': role.role_id},
                                     UpdateExpression=("SET TotalPermissions=:tp, RepoablePermissions=:rp, "
                                                       "RepoableServices=:rs"),
                                     ExpressionAttributeValues={
                                     ":tp": role.total_permissions,
                                     ":rp": role.repoable_permissions,
                                     ":rs": role.repoable_services
                                     })
        except BotoClientError as e:
            from repokid.repokid import LOGGER
            LOGGER.error('Dynamo table error: {}'.format(e))


def update_total_permissions(role):
    """Update total permissions for roleID"""
    try:
        DYNAMO_TABLE.update_item(Key={'RoleId': role.role_id},
                                 UpdateExpression="Set TotalPermissions=:tp",
                                 ExpressionAttributeValues={":tp": role.total_permissions})
    except BotoClientError as e:
        from repokid.repokid import LOGGER
        LOGGER.error('Dynamo table error: {}'.format(e))


def update_aardvark_data(account, aardvark_data, roles):
    """
    Given a blob of data from Aardvark, update the Aardvark data for all roles in the account
    """
    # Aardvark data is by ARN, we need to first get the active role ID since ARNs are resuable.

    # a secondary index of ARN --> RoleID might be another way to solve this,
    # but creating secondary index didn't work in testing.  Plenty of stuff like this:
    # https://forums.aws.amazon.com/thread.jspa?threadID=220139

    # so we'll start with getting active ARN -> role mapping by listing accounts and looking for active
    ARNtoRoleID = {}
    for roleID in roles_ids_for_account(account):
        role_data = _get_role_data(roleID, fields=['Arn', 'RoleId', 'Active'])
        if role_data['Active']:
            ARNtoRoleID[role_data['Arn']] = role_data['RoleId']

    for arn, aa_data in aardvark_data.items():
        try:
            role = roles.get_by_id(ARNtoRoleID[arn])
            role.aa_data = aa_data

            DYNAMO_TABLE.update_item(Key={'RoleId': ARNtoRoleID[arn]},
                                     UpdateExpression="SET AAData=:aa_data",
                                     ExpressionAttributeValues={
                                     ":aa_data": _empty_string_to_dynamo_replace(role.aa_data)
                                     })
        except KeyError:
            # if we get here we have AA data for a role we don't know about or an inactive role, either way it's fine
            pass
        except BotoClientError as e:
            from repokid.repokid import LOGGER
            LOGGER.error('Dynamo table error: {}'.format(e))


def update_role_data(role, current_policy):
    """Given role data either add it to the datastore, add a revision of the policies, or refresh updated time"""
    from repokid.repokid import LOGGER

    # policy_entry: source, discovered, policy
    stored_role = _get_role_data(role.role_id, fields=['Policies'])

    if stored_role:
        # is the policy list the same as the last we had?
        if current_policy != _empty_string_from_dynamo_replace(stored_role['Policies'][-1]['Policy']):
            add_new_policy_version(role, current_policy, 'Scan')
            LOGGER.info('{} has different inline policies than last time, adding to role store'.format(role.arn))

        _refresh_updated_time(role.role_id)
    else:
        _store_item(role, current_policy)
        LOGGER.info('Added new role ({}): {}'.format(role.role_id, role.arn))

    role.policies = get_role_data(role.role_id, fields=['Policies'])['Policies']


def update_stats(roles, source='Scan'):
    for role in roles:
        cur_stats = {'Date': datetime.utcnow().isoformat(),
                     'DisqualifiedBy': role.disqualified_by,
                     'PermissionsCount': role.total_permissions,
                     'Source': source}

        try:
            DYNAMO_TABLE.update_item(Key={'RoleId': role.role_id},
                                     UpdateExpression=("SET #statsarray = list_append(if_not_exists"
                                                       "(#statsarray, :empty_list), :stats)"),
                                     ExpressionAttributeNames={"#statsarray": "Stats"},
                                     ExpressionAttributeValues={":empty_list": [], ":stats": [cur_stats]})

        except BotoClientError as e:
            from repokid.repokid import LOGGER
            LOGGER.error('Dynamo table error: {}'.format(e))


def _refresh_updated_time(roleID):
    """Refresh a role's update time to now"""
    try:
        DYNAMO_TABLE.update_item(Key={'RoleId': roleID},
                                 UpdateExpression="SET Refreshed = :cur_time",
                                 ExpressionAttributeValues={
                                 ":cur_time": datetime.utcnow().isoformat()
                                 })
    except BotoClientError as e:
        from repokid.repokid import LOGGER
        LOGGER.error('Dynamo table error: {}'.format(e))


def roles_ids_for_account(account_number):
    """Get a list of all active role IDs for a given account number"""
    role_ids = set()
    try:
        results = DYNAMO_TABLE.query(IndexName='Account',
                                     ProjectionExpression='RoleId',
                                     KeyConditionExpression='Account = :act',
                                     ExpressionAttributeValues={':act': account_number})
        role_ids.update([return_dict['RoleId'] for return_dict in results.get('Items')])

        while 'LastEvaluatedKey' in results:
            results = DYNAMO_TABLE.query(IndexName='Account',
                                         ProjectionExpression='RoleId',
                                         KeyConditionExpression='Account = :act',
                                         ExpressionAttributeValues={':act': account_number},
                                         ExclusiveStartKey=results.get('LastEvaluatedKey'))
            role_ids.update([return_dict['RoleId'] for return_dict in results.get('Items')])
    except BotoClientError as e:
        from repokid.repokid import LOGGER
        LOGGER.error('Dynamo table error: {}'.format(e))

    return role_ids


def role_ids_for_all_accounts():
    role_ids = []

    try:
        response = DYNAMO_TABLE.scan(ProjectionExpression='RoleId')
        role_ids.extend([role_dict['RoleId'] for role_dict in response['Items']])

        while 'LastEvaluatedKey' in response:
            response = DYNAMO_TABLE.scan(ProjectionExpression='RoleId',
                                         ExclusiveStartKey=response['LastEvaluatedKey'])
            role_ids.extend([role_dict['RoleId'] for role_dict in response['Items']])
    except BotoClientError as e:
        from repokid.repokid import LOGGER
        LOGGER.error('Dynamo table error: {}'.format(e))

    return role_ids


def _get_role_data(roleID, fields=None):
    """Get raw role data, not to be used externally because this data still has dynamo empty string placeholders"""
    try:
        if fields:
            response = DYNAMO_TABLE.get_item(Key={'RoleId': roleID}, AttributesToGet=fields)
        else:
            response = DYNAMO_TABLE.get_item(Key={'RoleId': roleID})
    except BotoClientError as e:
        from repokid.repokid import LOGGER
        LOGGER.error('Dynamo table error: {}'.format(e))
    else:
        if 'Item' in response:
            return response['Item']
        else:
            return None


def find_and_mark_inactive(account_number, active_roles):
    """Mark roles that used to be active but weren't in current role listing inactive"""
    from repokid.repokid import LOGGER
    active_roles = set(active_roles)
    known_roles = set(roles_ids_for_account(account_number))
    inactive_roles = known_roles - active_roles

    for roleID in inactive_roles:
        role_dict = _get_role_data(roleID, fields=['Active', 'Arn'])
        if role_dict['Active']:
            try:
                DYNAMO_TABLE.update_item(Key={'RoleId': roleID},
                                         UpdateExpression="SET Active = :false",
                                         ExpressionAttributeValues={":false": False})
            except BotoClientError as e:
                LOGGER.error('Dynamo table error: {}'.format(e))
            else:
                LOGGER.info('Marked role ({}): {} inactive'.format(roleID, role_dict['Arn']))


def update_filtered_roles(filtered_roles):
    """Update roles with information about which filter(s) disqualified them"""
    for role in filtered_roles:
        try:
            DYNAMO_TABLE.update_item(Key={'RoleId': role.role_id},
                                     UpdateExpression="SET DisqualifiedBy = :dqby",
                                     ExpressionAttributeValues={":dqby": role.disqualified_by})
        except BotoClientError as e:
            from repokid.repokid import LOGGER
            LOGGER.error('Dynamo table error: {}'.format(e))


def add_new_policy_version(role, current_policy, update_source):
    """Store a new version of the current policies in the historical policy data for a role.
    Update source should be either 'Scan', 'Repo', or 'Restore'
    """
    role_data = _get_role_data(role.role_id, fields=['Policies'])
    new_item_index = len(role_data['Policies'])

    try:
        policy_entry = {'Source': update_source, 'Discovered': datetime.utcnow().isoformat(), 'Policy': current_policy}

        DYNAMO_TABLE.update_item(Key={'RoleId': role.role_id},
                                 UpdateExpression="SET #polarray[{}] = :pol".format(new_item_index),
                                 ExpressionAttributeNames={"#polarray": "Policies"},
                                 ExpressionAttributeValues={":pol": _empty_string_to_dynamo_replace(policy_entry)})

    except BotoClientError as e:
        from repokid.repokid import LOGGER
        LOGGER.error('Dynamo table error: {}'.format(e))


def set_repoed(roleID):
    """Marks a role ID as repoed now"""
    try:
        DYNAMO_TABLE.update_item(Key={'RoleId': roleID},
                                 UpdateExpression="SET Repoed = :now, RepoableServices = :el",
                                 ExpressionAttributeValues={":now": datetime.utcnow().isoformat(),
                                                            ":el": []})
    except BotoClientError as e:
        from repokid.repokid import LOGGER
        LOGGER.error('Dynamo table error: {}'.format(e))


def _store_item(role, current_policy):
    """Store initial version of role information"""
    policy_entry = {'Source': 'Scan', 'Discovered': datetime.utcnow().isoformat(), 'Policy': current_policy}

    role.policies = [policy_entry]
    role.refreshed = datetime.utcnow().isoformat()
    role.active = True
    role.repoed = 'Never'

    try:
        DYNAMO_TABLE.put_item(Item={'Arn': role.arn,
                                    'CreateDate': role.create_date.isoformat(),
                                    'RoleId': role.role_id,
                                    'RoleName': role.role_name,
                                    'Account': role.account,
                                    'Policies': [_empty_string_to_dynamo_replace(policy_entry)],
                                    'Refreshed': role.refreshed,
                                    'Active': role.active,
                                    'Repoed': role.repoed})
    except BotoClientError as e:
        from repokid.repokid import LOGGER
        LOGGER.error('Dynamo table error: {}'.format(e))


def _empty_string_to_dynamo_replace(obj):
    """Traverse a potentially nested object and replace all instances of an empty string with a placeholder"""
    if isinstance(obj, dict):
        return {k: _empty_string_to_dynamo_replace(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_empty_string_to_dynamo_replace(elem) for elem in obj]
    else:
        if str(obj) == '':
            obj = DYNAMO_EMPTY_STRING
        return obj


def _empty_string_from_dynamo_replace(obj):
    """Traverse a potentially nested object and replace all instances of placeholder with empty string"""
    if isinstance(obj, dict):
        return {k: _empty_string_from_dynamo_replace(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_empty_string_from_dynamo_replace(elem) for elem in obj]
    else:
        if str(obj) == DYNAMO_EMPTY_STRING:
            obj = ''
        return obj


def get_role_data(roleID, fields=None):
    """Return all data stored about a given role ID"""
    role_data = _get_role_data(roleID, fields=fields)

    # have to swap out empty SID for public consumption
    if role_data and 'Policies' in role_data:
        role_data['Policies'] = _empty_string_from_dynamo_replace(role_data['Policies'])

    if role_data and 'AAData' in role_data:
        role_data['AAData'] = _empty_string_from_dynamo_replace(role_data['AAData'])
    return role_data


def get_active_role_names_in_account(account_number):
    """Get a dictionary with role IDs as key of role data for all active roles in a given account"""
    role_names = []
    for roleID in tqdm(roles_ids_for_account(account_number)):
        role_data = get_role_data(roleID, fields=['Active', 'RoleName'])
        if role_data['Active']:
            role_names.append(role_data['RoleName'])
    return role_names
