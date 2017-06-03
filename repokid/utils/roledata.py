from botocore.exceptions import ClientError as BotoClientError
import boto3
from cloudaux.aws.sts import boto3_cached_conn
from datetime import datetime
import sys
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
            assume_role=dynamo_config['assume_role'],
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


def update_repoable_data(repoable_data):
    """Update total permissions, repoable permissions, and repoable services for an account"""
    for roleID, data in repoable_data.items():
        try:
            DYNAMO_TABLE.update_item(Key={'RoleId': roleID},
                                     UpdateExpression=("SET TotalPermissions=:tp, RepoablePermissions=:rp, "
                                                       "RepoableServices=:rs"),
                                     ExpressionAttributeValues={
                                     ":tp": data['TotalPermissions'],
                                     ":rp": data['RepoablePermissions'],
                                     ":rs": data['RepoableServices']
                                     })
        except BotoClientError as e:
            from repokid.repokid import LOGGER
            LOGGER.error('Dynamo table error: {}'.format(e))


def update_total_permissions(roleID, total_permissions):
    """Update total permissions for roleID"""
    try:
        DYNAMO_TABLE.update_item(Key={'RoleId': roleID},
                                 UpdateExpression="Set TotalPermissions=:tp",
                                 ExpressionAttributeValues={":tp": total_permissions})
    except BotoClientError as e:
        from repokid.repokid import LOGGER
        LOGGER.error('Dynamo table error: {}'.format(e))


def update_aardvark_data(account, aardvark_data):
    """
    Given a blob of data from Aardvark, update the Aardvark data for all roles in the account
    """
    # Aardvark data is by ARN, we need to first get the active role ID since ARNs are resuable.

    # a secondary index of ARN --> RoleID might be another way to solve this,
    # but creating secondary index didn't work in testing.  Plenty of stuff like this:
    # https://forums.aws.amazon.com/thread.jspa?threadID=220139

    # so we'll start with getting active ARN -> role mapping by listing accounts and looking for active
    ARNtoRoleID = {}
    for roleID in roles_for_account(account):
        role_data = _get_role_data(roleID)
        if role_data['Active']:
            ARNtoRoleID[role_data['Arn']] = role_data['RoleId']

    for arn, aa_data in aardvark_data.items():
        try:
            DYNAMO_TABLE.update_item(Key={'RoleId': ARNtoRoleID[arn]},
                                     UpdateExpression="SET AAData=:aa_data",
                                     ExpressionAttributeValues={
                                     ":aa_data": _empty_string_to_dynamo_replace(aa_data)
                                     })
        except KeyError:
            # if we get here we have AA data for a role we don't know about or an inactive role, either way it's fine
            pass
        except BotoClientError as e:
            from repokid.repokid import LOGGER
            LOGGER.error('Dynamo table error: {}'.format(e))


def update_role_data(role_dict):
    """Given role data either add it to the datastore, add a revision of the policies, or refresh updated time"""
    from repokid.repokid import LOGGER
    # need to convert to (stupid) DynamoDB empty string form
    if 'policies' in role_dict:
        role_dict['policies'] = _empty_string_to_dynamo_replace(role_dict['policies'])

    # policy_entry: source, discovered, policy
    stored_role = _get_role_data(role_dict['RoleId'])
    if stored_role:
        # is the policy list the same as the last we had?
        if not role_dict['policies'] == stored_role['Policies'][-1]['Policy']:
            add_new_policy_version(role_dict, 'Scan')
            LOGGER.info('{} has different inline policies than last time, adding to role store'.format(
                        role_dict['Arn']))
        _refresh_updated_time(role_dict['RoleId'])
    else:
        _store_item(role_dict)
        LOGGER.info('Added new role ({}): {}'.format(role_dict['RoleId'], role_dict['Arn']))


def update_stats(source='Scan', roleID=None):
    from repokid.repokid import CUR_ACCOUNT_NUMBER

    for roleID, role_data in ({roleID: _get_role_data(roleID)}.items() if roleID
                              else get_data_for_active_roles_in_account(CUR_ACCOUNT_NUMBER).items()):
        cur_stats = {'Date': datetime.utcnow().isoformat(),
                     'DisqualifiedBy': role_data.get('DisqualifiedBy', []),
                     'PermissionsCount': role_data['TotalPermissions'],
                     'Source': source}

        try:
            DYNAMO_TABLE.update_item(Key={'RoleId': roleID},
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


def roles_for_account(account_number):
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


def _get_role_data(roleID):
    """Get raw role data, not to be used externally because this data still has dynamo empty string placeholders"""
    try:
        response = DYNAMO_TABLE.get_item(Key={'RoleId': roleID})
    except BotoClientError as e:
        from repokid.repokid import LOGGER
        LOGGER.error('Dynamo table error: {}'.format(e))
    else:
        if 'Item' in response:
            return response['Item']
        else:
            return None


def find_and_mark_inactive(active_roles):
    """Mark roles that used to be active but weren't in current role listing inactive"""
    from repokid.repokid import CUR_ACCOUNT_NUMBER
    from repokid.repokid import LOGGER
    active_roles = set(active_roles)
    known_roles = set(roles_for_account(CUR_ACCOUNT_NUMBER))
    inactive_roles = known_roles - active_roles

    for roleID in inactive_roles:
        role_dict = _get_role_data(roleID)
        if role_dict['Active']:
            try:
                DYNAMO_TABLE.update_item(Key={'RoleId': roleID},
                                         UpdateExpression="SET Active = :false",
                                         ExpressionAttributeValues={":false": False})
            except BotoClientError as e:
                LOGGER.error('Dynamo table error: {}'.format(e))
            else:
                LOGGER.info('Marked role ({}): {} inactive'.format(roleID, role_dict['Arn']))


def update_filtered_roles(roles_filtered_list):
    """Update roles with information about which filter(s) disqualified them"""
    for roleID, filteredlist in roles_filtered_list.items():
        try:
            DYNAMO_TABLE.update_item(Key={'RoleId': roleID},
                                     UpdateExpression="SET DisqualifiedBy = :dqby",
                                     ExpressionAttributeValues={":dqby": filteredlist})
        except BotoClientError as e:
            from repokid.repokid import LOGGER
            LOGGER.error('Dynamo table error: {}'.format(e))


def add_new_policy_version(role_dict, update_source):
    """Store a new version of the current policies in the historical policy data for a role.
    Update source should be either 'Scan', 'Repo', or 'Restore'
    """
    role = _get_role_data(role_dict['RoleId'])
    new_item_index = len(role['Policies'])
    try:
        policy = {'Source': update_source, 'Discovered': datetime.utcnow().isoformat(), 'Policy': role_dict['policies']}
        DYNAMO_TABLE.update_item(Key={'RoleId': role_dict['RoleId']},
                                 UpdateExpression="SET #polarray[{}] = :pol".format(new_item_index),
                                 ExpressionAttributeNames={"#polarray": "Policies"},
                                 ExpressionAttributeValues={":pol": policy})
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


def _store_item(role_dict):
    """Store initial version of role information"""
    policy = {'Source': 'Scan', 'Discovered': datetime.utcnow().isoformat(), 'Policy': role_dict['policies']}
    try:
        DYNAMO_TABLE.put_item(Item={'Arn': role_dict['Arn'],
                                    'CreateDate': role_dict['CreateDate'].isoformat(),
                                    'RoleId': role_dict['RoleId'],
                                    'RoleName': role_dict['RoleName'],
                                    'Account': role_dict['Arn'].split(':')[4],
                                    'Policies': [policy],
                                    'Refreshed': datetime.utcnow().isoformat(),
                                    'Active': True,
                                    'Repoed': 'Never'})
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


def get_role_data(roleID):
    """Return all data stored about a given role ID"""
    role_data = _get_role_data(roleID)

    # have to swap out empty SID for public consumption
    if role_data and 'Policies' in role_data:
        role_data['Policies'] = _empty_string_from_dynamo_replace(role_data['Policies'])

    if role_data and 'AAData' in role_data:
        role_data['AAData'] = _empty_string_from_dynamo_replace(role_data['AAData'])
    return role_data


def get_data_for_active_roles_in_account(account_number):
    """Get a dictionary with role IDs as key of role data for all active roles in a given account"""
    data = {}
    for roleID in tqdm(roles_for_account(account_number)):
        role_data = get_role_data(roleID)
        if role_data['Active']:
            data[roleID] = role_data
    return data
