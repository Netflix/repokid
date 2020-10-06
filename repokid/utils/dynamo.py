import copy
import datetime
from functools import wraps
import logging

import boto3
from botocore.exceptions import ClientError as BotoClientError
from cloudaux.aws.sts import boto3_cached_conn as boto3_cached_conn

LOGGER = logging.getLogger("repokid")
# used as a placeholder for empty SID to work around this: https://github.com/aws/aws-sdk-js/issues/833
DYNAMO_EMPTY_STRING = "---DYNAMO-EMPTY-STRING---"


def catch_boto_error(func):
    @wraps(func)
    def decorated_func(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except BotoClientError as e:
            LOGGER.error("Dynamo table error: {}".format(e))

    return decorated_func


@catch_boto_error
def add_to_end_of_list(
    dynamo_table, role_id, field_name, object_to_add, max_retries=5, _retries=0
):
    """Append object to DynamoDB list, removing the first element if item exceeds max size."""
    try:
        dynamo_table.update_item(
            Key={"RoleId": role_id},
            UpdateExpression=(
                "SET #updatelist = list_append(if_not_exists(#updatelist,"
                ":empty_list), :object_to_add)"
            ),
            ExpressionAttributeNames={"#updatelist": field_name},
            ExpressionAttributeValues={
                ":empty_list": [],
                ":object_to_add": [_empty_string_to_dynamo_replace(object_to_add)],
            },
        )
    except BotoClientError as e:
        error = e.response.get("Error", {})
        code = error.get("Code")
        message = error.get("Message")
        if (
            code == "ValidationException"
            and "maximum allowed size" in message
            and _retries < max_retries
        ):
            LOGGER.info(
                "Removing first element from %s for role %s to keep item under maximum size",
                field_name,
                role_id,
            )
            _retries += 1
            dynamo_table.update_item(
                Key={"RoleId": role_id},
                UpdateExpression="REMOVE #updatelist[0]",
                ExpressionAttributeNames={"#updatelist": field_name},
            )
            add_to_end_of_list(
                dynamo_table, role_id, field_name, object_to_add, _retries=_retries
            )
        else:
            raise


def dynamo_get_or_create_table(**dynamo_config):
    """
    Create a new table or get a reference to an existing Dynamo table named 'repokid_roles' that will store data all
    data for Repokid.  Return a table with a reference to the dynamo resource

    Args:
        dynamo_config (kwargs):
            account_number (string)
            assume_role (string) optional
            session_name (string)
            region (string)
            endpoint (string)

    Returns:
        dynamo_table object
    """
    if "localhost" in dynamo_config["endpoint"]:
        resource = boto3.resource(
            "dynamodb", region_name="us-east-1", endpoint_url=dynamo_config["endpoint"]
        )
    else:
        resource = boto3_cached_conn(
            "dynamodb",
            service_type="resource",
            account_number=dynamo_config["account_number"],
            assume_role=dynamo_config.get("assume_role", None),
            session_name=dynamo_config["session_name"],
            region=dynamo_config["region"],
        )

    for table in resource.tables.all():
        if table.name == "repokid_roles":
            return table

    table = None
    try:
        table = resource.create_table(
            TableName="repokid_roles",
            KeySchema=[{"AttributeName": "RoleId", "KeyType": "HASH"}],  # Partition key
            AttributeDefinitions=[
                {"AttributeName": "RoleId", "AttributeType": "S"},
                {"AttributeName": "RoleName", "AttributeType": "S"},
                {"AttributeName": "Account", "AttributeType": "S"},
            ],
            ProvisionedThroughput={"ReadCapacityUnits": 50, "WriteCapacityUnits": 50},
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "Account",
                    "KeySchema": [{"AttributeName": "Account", "KeyType": "HASH"}],
                    "Projection": {"ProjectionType": "KEYS_ONLY"},
                    "ProvisionedThroughput": {
                        "ReadCapacityUnits": 10,
                        "WriteCapacityUnits": 10,
                    },
                },
                {
                    "IndexName": "RoleName",
                    "KeySchema": [{"AttributeName": "RoleName", "KeyType": "HASH"}],
                    "Projection": {"ProjectionType": "KEYS_ONLY"},
                    "ProvisionedThroughput": {
                        "ReadCapacityUnits": 10,
                        "WriteCapacityUnits": 10,
                    },
                },
            ],
        )

    except BotoClientError as e:
        LOGGER.error(e, exc_info=True)
    return table


def find_role_in_cache(dynamo_table, account_number, role_name):
    """Return role dictionary for active role with name in account

    Args:
        account_number (string)
        role_name (string)

    Returns:
        string: RoleID for active role with name in given account, else None
    """
    results = dynamo_table.query(
        IndexName="RoleName",
        KeyConditionExpression="RoleName = :rn",
        ExpressionAttributeValues={":rn": role_name},
    )
    role_id_candidates = [return_dict["RoleId"] for return_dict in results.get("Items")]

    if len(role_id_candidates) > 1:
        for role_id in role_id_candidates:
            role_data = get_role_data(
                dynamo_table, role_id, fields=["Account", "Active"]
            )
            if role_data["Account"] == account_number and role_data["Active"]:
                return role_id
    elif len(role_id_candidates) == 1:
        return role_id_candidates[0]
    else:
        return None


@catch_boto_error
def get_role_data(dynamo_table, roleID, fields=None):
    """
    Get role data as a dictionary for a given role by ID

    Args:
        roleID (string)

    Returns:
        dict: data for the role if it exists, else None
    """
    if fields:
        response = dynamo_table.get_item(Key={"RoleId": roleID}, AttributesToGet=fields)
    else:
        response = dynamo_table.get_item(Key={"RoleId": roleID})

    if response and "Item" in response:
        return _empty_string_from_dynamo_replace(response["Item"])


@catch_boto_error
def role_ids_for_account(dynamo_table, account_number):
    """
    Get a list of all role IDs in a given account by querying the Dynamo secondary index 'account'

    Args:
        account_number (string)

    Returns:
        list: role ids in given account
    """
    role_ids = set()

    results = dynamo_table.query(
        IndexName="Account",
        KeyConditionExpression="Account = :act",
        ExpressionAttributeValues={":act": account_number},
    )
    role_ids.update([return_dict["RoleId"] for return_dict in results.get("Items")])

    while "LastEvaluatedKey" in results:
        results = dynamo_table.query(
            IndexName="Account",
            KeyConditionExpression="Account = :act",
            ExpressionAttributeValues={":act": account_number},
            ExclusiveStartKey=results.get("LastEvaluatedKey"),
        )
        role_ids.update([return_dict["RoleId"] for return_dict in results.get("Items")])
    return role_ids


@catch_boto_error
def role_ids_for_all_accounts(dynamo_table):
    """
    Get a list of all role IDs for all accounts by scanning the Dynamo table

    Args:
        None

    Returns:
        list: role ids in all accounts
    """
    role_ids = []

    response = dynamo_table.scan(ProjectionExpression="RoleId")
    role_ids.extend([role_dict["RoleId"] for role_dict in response["Items"]])

    while "LastEvaluatedKey" in response:
        response = dynamo_table.scan(
            ProjectionExpression="RoleId",
            ExclusiveStartKey=response["LastEvaluatedKey"],
        )
        role_ids.extend([role_dict["RoleId"] for role_dict in response["Items"]])
    return role_ids


@catch_boto_error
def set_role_data(dynamo_table, role_id, update_keys):
    if not update_keys:
        return

    update_expression = "SET "
    expression_attribute_names = {}
    expression_attribute_values = {}
    count = 0
    for key, value in update_keys.items():
        count += 1

        if count > 1:
            update_expression += ", "

        value = _empty_string_to_dynamo_replace(value)

        update_expression += f"#expr{count} = :val{count}"
        expression_attribute_names[f"#expr{count}"] = key
        expression_attribute_values[f":val{count}"] = value

    update_item_inputs = {
        "Key": {"RoleId": role_id},
        "UpdateExpression": update_expression,
        "ExpressionAttributeNames": expression_attribute_names,
        "ExpressionAttributeValues": expression_attribute_values,
    }
    LOGGER.debug("updating dynamodb with inputs %s", update_item_inputs)
    dynamo_table.update_item(**update_item_inputs)


def store_initial_role_data(
    dynamo_table,
    arn,
    create_date,
    role_id,
    role_name,
    account_number,
    current_policy,
    tags,
):
    """
    Store the initial version of a role in Dynamo

    Args:
        role (Role)
        current_policy (dict)

    Returns:
        None
    """
    policy_entry = {
        "Source": "Scan",
        "Discovered": datetime.datetime.utcnow().isoformat(),
        "Policy": current_policy,
    }

    role_dict = {
        "Arn": arn,
        "CreateDate": create_date.isoformat(),
        "RoleId": role_id,
        "RoleName": role_name,
        "Account": account_number,
        "Policies": [policy_entry],
        "Refreshed": datetime.datetime.utcnow().isoformat(),
        "Active": True,
        "Repoed": "Never",
        "Tags": tags,
    }

    store_dynamo = copy.copy(role_dict)

    dynamo_table.put_item(Item=_empty_string_to_dynamo_replace(store_dynamo))
    # we want to store CreateDate as a string but keep it as a datetime, so put it back here
    role_dict["CreateDate"] = create_date
    return role_dict


def _empty_string_from_dynamo_replace(obj):
    """
    Traverse a potentially nested object and replace all Dynamo placeholders with actual empty strings

    Args:
        obj (object)

    Returns:
        object: Object with original empty strings
    """
    if isinstance(obj, dict):
        return {k: _empty_string_from_dynamo_replace(v) for k, v in list(obj.items())}
    elif isinstance(obj, list):
        return [_empty_string_from_dynamo_replace(elem) for elem in obj]
    else:
        if str(obj) == DYNAMO_EMPTY_STRING:
            obj = ""
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
        return {k: _empty_string_to_dynamo_replace(v) for k, v in list(obj.items())}
    elif isinstance(obj, list):
        return [_empty_string_to_dynamo_replace(elem) for elem in obj]
    else:
        try:
            if str(obj) == "":
                obj = DYNAMO_EMPTY_STRING
        except UnicodeEncodeError:
            obj = DYNAMO_EMPTY_STRING
        return obj
