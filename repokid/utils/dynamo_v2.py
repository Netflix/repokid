import datetime
import logging
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Union

import boto3
from botocore.exceptions import ClientError as BotoClientError
from cloudaux.aws.sts import boto3_cached_conn
from mypy_boto3_dynamodb.service_resource import Table
from mypy_boto3_dynamodb.type_defs import GlobalSecondaryIndexTypeDef

from repokid import CONFIG
from repokid.exceptions import RoleNotFoundError

DYNAMO_EMPTY_STRING = "---DYNAMO-EMPTY-STRING---"

logger = logging.getLogger("repokid")


def _empty_string_from_dynamo_replace(
    obj: Union[Dict[str, Any], List[Any]]
) -> Union[Dict[str, Any], List[Any]]:
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


def _empty_string_to_dynamo_replace(
    obj: Union[Dict[str, Any], List[Any]]
) -> Union[Dict[str, Any], List[Any]]:
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


def _datetime_to_string_replace(
    obj: Union[Dict[str, Any], List[Any]]
) -> Union[Dict[str, Any], List[Any]]:
    if isinstance(obj, dict):
        return {k: _datetime_to_string_replace(v) for k, v in list(obj.items())}
    elif isinstance(obj, list):
        return [_datetime_to_string_replace(elem) for elem in obj]
    else:
        if isinstance(obj, datetime.datetime):
            obj = obj.strftime("%Y-%m-%d %H:%M")
        return obj


def dynamo_get_or_create_table(
    account_number: str,
    session_name: str,
    region: str,
    endpoint: str,
    assume_role: Optional[str] = "",
) -> Table:
    """
    Create a new table or get a reference to an existing Dynamo table named 'repokid_roles' that will store data all
    data for Repokid.  Return a table with a reference to the dynamo resource

    Args:
        account_number (string)
        assume_role (string) optional
        session_name (string)
        region (string)
        endpoint (string)

    Returns:
        dynamo_table object
    """
    if "localhost" in endpoint:
        resource = boto3.resource(
            "dynamodb", region_name="us-east-1", endpoint_url=endpoint
        )
    else:
        resource = boto3_cached_conn(
            "dynamodb",
            service_type="resource",
            account_number=account_number,
            assume_role=assume_role or None,
            session_name=session_name,
            region=region,
        )

    for table in resource.tables.all():
        if table.name == "repokid_roles":
            return table

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
            GlobalSecondaryIndexTypeDef(
                {
                    "IndexName": "Account",
                    "KeySchema": [{"AttributeName": "Account", "KeyType": "HASH"}],
                    "Projection": {"ProjectionType": "KEYS_ONLY"},
                    "ProvisionedThroughput": {
                        "ReadCapacityUnits": 10,
                        "WriteCapacityUnits": 10,
                    },
                }
            ),
            GlobalSecondaryIndexTypeDef(
                {
                    "IndexName": "RoleName",
                    "KeySchema": [{"AttributeName": "RoleName", "KeyType": "HASH"}],
                    "Projection": {"ProjectionType": "KEYS_ONLY"},
                    "ProvisionedThroughput": {
                        "ReadCapacityUnits": 10,
                        "WriteCapacityUnits": 10,
                    },
                }
            ),
        ],
    )

    return table


def create_dynamodb_entry(values: Dict[str, Any], dynamo_table: Optional[Table] = None) -> None:
    table = dynamo_table or ROLE_TABLE
    try:
        table.put_item(Item=values)
    except BotoClientError:
        logger.error("failed to create dynamodb item")
        logger.debug("dynamodb creation failure details", extra={"values": values})
        raise


def get_role_by_id(
    role_id: str, fields: Optional[List[str]] = None, dynamo_table: Optional[Table] = None
) -> Dict[str, Any]:
    table = dynamo_table or ROLE_TABLE
    if fields:
        response = table.get_item(
            Key={"RoleId": role_id}, AttributesToGet=fields
        )
    else:
        response = table.get_item(Key={"RoleId": role_id})

    if response and "Item" in response:
        return _empty_string_from_dynamo_replace(response["Item"])
    else:
        raise RoleNotFoundError(f"Role ID {role_id} not found in DynamoDB")


def get_role_by_name(
    account_id: str,
    role_name: str,
    fields: Optional[List[str]] = None,
    dynamo_table: Optional[Table] = None,
) -> Dict[str, Any]:
    table = dynamo_table or ROLE_TABLE
    results = table.query(
        IndexName="RoleName",
        KeyConditionExpression="RoleName = :rn",
        ExpressionAttributeValues={":rn": role_name},
    )
    items = results.get("Items")
    if len(items) < 1:
        raise RoleNotFoundError(f"{role_name} in {account_id} not found in DynamoDB")

    if len(items) > 1:
        # multiple results, so we'll grab the first match that's active
        for r in items:
            if r.get("Active"):
                return r

    # we only have one result
    return items[0]


def set_role_data(
    role_id: str, update_keys: Dict[str, Any], dynamo_table: Optional[Table] = None
) -> None:
    table = dynamo_table or ROLE_TABLE
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
        value = _datetime_to_string_replace(value)

        update_expression += f"#expr{count} = :val{count}"
        expression_attribute_names[f"#expr{count}"] = key
        expression_attribute_values[f":val{count}"] = value

    update_item_inputs = {
        "Key": {"RoleId": role_id},
        "UpdateExpression": update_expression,
        "ExpressionAttributeNames": expression_attribute_names,
        "ExpressionAttributeValues": expression_attribute_values,
    }
    logger.debug("updating dynamodb with inputs %s", update_item_inputs)
    table.update_item(
        Key={"RoleId": role_id},
        UpdateExpression=update_expression,
        ExpressionAttributeNames=expression_attribute_names,
        ExpressionAttributeValues=expression_attribute_values,
    )


ROLE_TABLE = dynamo_get_or_create_table(**CONFIG["dynamo_db"])
