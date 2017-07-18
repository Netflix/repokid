from datetime import datetime
import sys
import time

import boto3
from botocore.exceptions import ClientError as BotoClientError
from cloudaux.aws.sts import boto3_cached_conn

import repokid.repokid

# used as a placeholder for empty SID to work around this: https://github.com/aws/aws-sdk-js/issues/833
DYNAMO_EMPTY_STRING = "---DYNAMO-EMPTY-STRING---"
DYNAMO_TABLE = None


def add_new_policy_version(role, current_policy, update_source):
    """
    Create a new entry in the history of policy versions in Dynamo. The entry contains the source of the new policy:
    (scan, repo, or restore) the current time, and the current policy contents. Updates the role's policies with the
    full policies including the latest.

    Args:
        role (Role)
        current_policy (dict)
        update_source (string): ['Repo', 'Scan', 'Restore']

    Returns:
        None
    """
    cur_role_data = _get_role_data(role.role_id, fields=['Policies'])
    new_item_index = len(cur_role_data.get('Policies', []))

    try:
        policy_entry = {'Source': update_source, 'Discovered': datetime.utcnow().isoformat(), 'Policy': current_policy}

        DYNAMO_TABLE.update_item(Key={'RoleId': role.role_id},
                                 UpdateExpression="SET #polarray[{}] = :pol".format(new_item_index),
                                 ExpressionAttributeNames={"#polarray": "Policies"},
                                 ExpressionAttributeValues={":pol": _empty_string_to_dynamo_replace(policy_entry)})

    except BotoClientError as e:
        from repokid.repokid import LOGGER
        LOGGER.error('Dynamo table error: {}'.format(e))

    role.policies = get_role_data(role.role_id, fields=['Policies'])['Policies']


def dynamo_get_or_create_table(**dynamo_config):
    """
    Create a new table or get a reference to an existing Dynamo table named 'repokid_roles' that will store data all
    data for Repokid.  Set the global DYNAMO_TABLE object with a reference to the resource handle.

    Args:
        dynamo_config (kwargs):
            account_number (string)
            assume_role (string) optional
            session_name (string)
            region (string)
            endpoint (string)

    Returns:
        None
    """
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


def find_and_mark_inactive(account_number, active_roles):
    """
    Mark roles in the account that aren't currently active inactive. Do this by getting all roles in the account and
    subtracting the active roles, any that are left are inactive and should be marked thusly.

    Args:
        account_number (string)
        active_roles (set): the currently active roles discovered in the most recent scan

    Returns:
        None
    """
    from repokid.repokid import LOGGER
    active_roles = set(active_roles)
    known_roles = set(role_ids_for_account(account_number))
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


def get_role_data(roleID, fields=None):
    """
    Get raw role data as a dictionary for a given role by ID

    Args:
        roleID (string)

    Returns:
        dict: data for the role if it exists, else None
    """
    role_data = _get_role_data(roleID, fields=fields)

    # have to swap out empty SID for public consumption
    if role_data and 'Policies' in role_data:
        role_data['Policies'] = _empty_string_from_dynamo_replace(role_data['Policies'])

    if role_data and 'AAData' in role_data:
        role_data['AAData'] = _empty_string_from_dynamo_replace(role_data['AAData'])
    return role_data


def role_ids_for_account(account_number):
    """
    Get a list of all role IDs in a given account by querying the Dynamo secondary index 'account'

    Args:
        account_number (string)

    Returns:
        list: role ids in given account
    """
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
    """
    Get a list of all role IDs for all accounts by scanning the Dynamo table

    Args:
        None

    Returns:
        list: role ids in all accounts
    """
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


def set_repoed(role_id):
    """
    Marks a role (by ID) as having been repoed now (utcnow) as string in Dynamo

    Args:
        role_id (string)

    Returns:
        None
    """
    try:
        DYNAMO_TABLE.update_item(Key={'RoleId': role_id},
                                 UpdateExpression="SET Repoed = :now, RepoableServices = :el",
                                 ExpressionAttributeValues={":now": datetime.utcnow().isoformat(),
                                                            ":el": []})
    except BotoClientError as e:
        from repokid.repokid import LOGGER
        LOGGER.error('Dynamo table error: {}'.format(e))


def update_aardvark_data(aardvark_data, roles):
    """
    Update Aardvark data for a given set of roles by looking for the ARN in the aardvark data dict.
    If the ARN is in Aardvark data update the role's aa_data attribute and Dynamo.

    Args:
        aardvark_data (dict): A dict of Aardvark data from an account
        roles (Roles): a list of all the role objects to update data for

    Returns:
        None
    """
    for role in roles:
        if role.arn in aardvark_data:
            role.aa_data = aardvark_data[role.arn]
        try:
            DYNAMO_TABLE.update_item(Key={'RoleId': role.role_id},
                                     UpdateExpression="SET AAData=:aa_data",
                                     ExpressionAttributeValues={
                                     ":aa_data": _empty_string_to_dynamo_replace(role.aa_data)
                                     })
        except BotoClientError as e:
            from repokid.repokid import LOGGER
            LOGGER.error('Dynamo table error: {}'.format(e))


def update_no_repo_permissions(role, newly_added_permissions):
    """
    Update Dyanmo entry for newly added permissions. Any that were newly detected get added with an expiration
    date of now plus the config setting for 'repo_requirements': 'exclude_new_permissions_for_days'. Expired entries
    get deleted. Also update the role object with the new no-repo-permissions.

    Args:
        role
        newly_added_permissions (set)

    Returns:
        None
    """
    current_ignored_permissions = _get_role_data(role.role_id, fields=['NoRepoPermissions']).get(
                                                 'NoRepoPermissions', {})
    new_ignored_permissions = {}

    current_time = int(time.time())
    new_perms_expire_time = current_time + (
        24 * 60 * 60 * repokid.repokid.CONFIG['repo_requirements'].get('exclude_new_permissions_for_days', 14))

    # only copy non-expired items to the new dictionary
    for permission, expire_time in current_ignored_permissions.items():
        if expire_time > current_time:
            new_ignored_permissions[permission] = current_ignored_permissions[permission]

    for permission in newly_added_permissions:
        new_ignored_permissions[permission] = new_perms_expire_time

    role.no_repo_permissions = new_ignored_permissions

    try:
        DYNAMO_TABLE.update_item(Key={'RoleId': role.role_id},
                                 UpdateExpression="SET NoRepoPermissions=:nrp",
                                 ExpressionAttributeValues={":nrp": new_ignored_permissions})
    except BotoClientError as e:
        from repokid.repokid import LOGGER
        LOGGER.error('Dynamo table error: {}'.format(e))


def update_opt_out(role):
    """
    Update opt-out object for a role - remove (set to empty dict) any entries that have expired
    Opt-out objects should have the form {'expire': xxx, 'owner': xxx, 'reason': xxx}

    Args:
        role

    Returns:
        None
    """
    if role.opt_out and int(role.opt_out['expire']) < int(time.time()):
        try:
            DYNAMO_TABLE.update_item(Key={'RoleId': role.role_id},
                                     UpdateExpression="SET OptOut=:oo",
                                     ExpressionAttributeValues={":oo": {}})
        except BotoClientError as e:
            from repokid.repokid import LOGGER
            LOGGER.error('Dynamo table error: {}'.format(e))


def update_repoable_data(roles):
    """
    Update total permissions and repoable permissions count and a list of repoable services in Dynamo for each role

    Args:
        roles (Roles): a list of all the role objects to update data for

    Returns:
        None
    """
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


def update_role_data(role, current_policy):
    """
    Compare the current version of a policy for a role and what has been previously stored in Dynamo.
      - If current and new policy versions are different store the new version in Dynamo. Add any newly added
          permissions to temporary permission blacklist. Purge any old entries from permission blacklist.
      - Refresh the updated time on the role policy
      - If the role is completely new, store the first version in Dynamo
      - Updates the role with full history of policies, including current version

    Args:
        role (Role): current role being updated
        current_policy (dict): representation of the current policy version

    Returns:
        None
    """
    from repokid.repokid import LOGGER

    # policy_entry: source, discovered, policy
    stored_role = _get_role_data(role.role_id, fields=['OptOut', 'Policies'])

    if stored_role:
        # is the policy list the same as the last we had?
        old_policy = _empty_string_from_dynamo_replace(stored_role['Policies'][-1]['Policy'])
        if current_policy != old_policy:
            add_new_policy_version(role, current_policy, 'Scan')
            LOGGER.info('{} has different inline policies than last time, adding to role store'.format(role.arn))

            newly_added_permissions = repokid.repokid._find_newly_added_permissions(old_policy, current_policy)
        else:
            newly_added_permissions = set()

        update_no_repo_permissions(role, newly_added_permissions)
        update_opt_out(role)
        _refresh_updated_time(role.role_id)
    else:
        _store_item(role, current_policy)
        LOGGER.info('Added new role ({}): {}'.format(role.role_id, role.arn))

    role.policies = get_role_data(role.role_id, fields=['Policies']).get('Policies', [])


def update_stats(roles, source='Scan'):
    """
    Create a new stats entry for each role in a set of roles and add it to Dynamo

    Args:
        roles (Roles): a list of all the role objects to update data for
        source (string): the source of the new stats data (repo, scan, etc)

    Returns:
        None
    """
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


def update_filtered_roles(roles):
    """
    Update the disqualified by (applicable filters) in Dynamo for each role in a list of roles

    Args:
        roles (Roles)

    Returns:
        None
    """
    for role in roles:
        try:
            DYNAMO_TABLE.update_item(Key={'RoleId': role.role_id},
                                     UpdateExpression="SET DisqualifiedBy = :dqby",
                                     ExpressionAttributeValues={":dqby": role.disqualified_by})
        except BotoClientError as e:
            from repokid.repokid import LOGGER
            LOGGER.error('Dynamo table error: {}'.format(e))


def _empty_string_from_dynamo_replace(obj):
    """
    Traverse a potentially nested object and replace all Dynamo placeholders with actual empty strings

    Args:
        obj (object)

    Returns:
        object: Object with original empty strings
    """
    if isinstance(obj, dict):
        return {k: _empty_string_from_dynamo_replace(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_empty_string_from_dynamo_replace(elem) for elem in obj]
    else:
        if str(obj) == DYNAMO_EMPTY_STRING:
            obj = ''
        return obj


def _empty_string_to_dynamo_replace(obj):
    """
    Traverse a potentially nested object and replace all instances of an empty string with a placeholder

    Args:
        obj (object)

    Returns:
        object: Object with Dynamo friendly empty strings
    """
    if isinstance(obj, dict):
        return {k: _empty_string_to_dynamo_replace(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_empty_string_to_dynamo_replace(elem) for elem in obj]
    else:
        if str(obj) == '':
            obj = DYNAMO_EMPTY_STRING
        return obj


def _get_role_data(roleID, fields=None):
    """
    Get raw role data as a dictionary for a given role by ID
    Do not use for data presented to the user because this data still has dynamo empty string placeholders, use
    get_role_data() instead

    Args:
        roleID (string)

    Returns:
        dict: data for the role if it exists, else None
    """
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


def _refresh_updated_time(roleID):
    """
    Update refreshed time for given role ID to utcnow

    Args:
        rolesID (string): the role ID of the role to update

    Returns:
        None
    """
    try:
        DYNAMO_TABLE.update_item(Key={'RoleId': roleID},
                                 UpdateExpression="SET Refreshed = :cur_time",
                                 ExpressionAttributeValues={
                                 ":cur_time": datetime.utcnow().isoformat()
                                 })
    except BotoClientError as e:
        from repokid.repokid import LOGGER
        LOGGER.error('Dynamo table error: {}'.format(e))


def _store_item(role, current_policy):
    """
    Store the initial version of a role in Dynamo

    Args:
        role (Role)
        current_policy (dict)

    Returns:
        None
    """
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
