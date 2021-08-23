import datetime
import logging
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Set
from typing import TypeVar
from typing import Union

import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError as BotoClientError
from cloudaux.aws.sts import boto3_cached_conn
from mypy_boto3_dynamodb.service_resource import Table
from mypy_boto3_dynamodb.type_defs import AttributeDefinitionTypeDef
from mypy_boto3_dynamodb.type_defs import GlobalSecondaryIndexTypeDef

from repokid import CONFIG
from repokid.exceptions import DynamoDBError
from repokid.exceptions import DynamoDBMaxItemSizeError
from repokid.exceptions import RoleNotFoundError

DYNAMO_EMPTY_STRING = "---DYNAMO-EMPTY-STRING---"
T = TypeVar("T", str, Dict[Any, Any], List[Any])

logger = logging.getLogger("repokid")

_indexes = [
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
            "IndexName": "Arn",
            "KeySchema": [{"AttributeName": "Arn", "KeyType": "HASH"}],
            "Projection": {"ProjectionType": "ALL"},
            "ProvisionedThroughput": {
                "ReadCapacityUnits": 10,
                "WriteCapacityUnits": 10,
            },
        }
    ),
]


def _empty_string_from_dynamo_replace(obj: T) -> T:
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
        if isinstance(obj, str) and str == DYNAMO_EMPTY_STRING:
            return ""
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


def _has_index(table: Table, index_name: str) -> bool:
    for i in table.global_secondary_indexes:
        if i["IndexName"] == index_name:
            return True
    return False


def _attributes_from_index(
    index: GlobalSecondaryIndexTypeDef,
) -> List[AttributeDefinitionTypeDef]:
    attributes: List[AttributeDefinitionTypeDef] = []
    for attribute in index["KeySchema"]:
        attributes.append(
            {"AttributeName": attribute["AttributeName"], "AttributeType": "S"}
        )
    return attributes


def _ensure_indexes(
    table: Table, desired_indexes: List[GlobalSecondaryIndexTypeDef]
) -> None:
    to_add: List[GlobalSecondaryIndexTypeDef] = []
    for i in desired_indexes:
        if not _has_index(table, i["IndexName"]):
            to_add.append(i)

    index_updates = [{"Create": i} for i in to_add]
    attribute_updates = []
    for i in to_add:
        attribute_updates.extend(_attributes_from_index(i))

    if to_add:
        table.update(
            GlobalSecondaryIndexUpdates=index_updates,
            AttributeDefinitions=attribute_updates,
        )


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
            _ensure_indexes(table, _indexes)
            return table

    table = resource.create_table(
        TableName="repokid_roles",
        KeySchema=[{"AttributeName": "RoleId", "KeyType": "HASH"}],  # Partition key
        AttributeDefinitions=[
            {"AttributeName": "RoleId", "AttributeType": "S"},
            {"AttributeName": "RoleName", "AttributeType": "S"},
            {"AttributeName": "Account", "AttributeType": "S"},
            {"AttributeName": "Arn", "AttributeType": "S"},
        ],
        ProvisionedThroughput={"ReadCapacityUnits": 50, "WriteCapacityUnits": 50},
        GlobalSecondaryIndexes=_indexes,
    )

    return table


def create_dynamodb_entry(
    values: Dict[str, Any], dynamo_table: Optional[Table] = None
) -> None:
    table = dynamo_table or ROLE_TABLE
    for key, value in values.items():
        value = _empty_string_to_dynamo_replace(value)
        value = _datetime_to_string_replace(value)
        values[key] = value
    try:
        table.put_item(Item=values)
    except BotoClientError:
        logger.error("failed to create dynamodb item")
        logger.debug("dynamodb creation failure details", extra={"values": values})
        raise


def get_role_by_id(
    role_id: str,
    fields: Optional[List[str]] = None,
    dynamo_table: Optional[Table] = None,
) -> Dict[str, Any]:
    table = dynamo_table or ROLE_TABLE
    if fields:
        response = table.get_item(Key={"RoleId": role_id}, AttributesToGet=fields)
    else:
        response = table.get_item(Key={"RoleId": role_id})

    if response and "Item" in response:
        return _empty_string_from_dynamo_replace(response["Item"])
    else:
        raise RoleNotFoundError(f"Role ID {role_id} not found in DynamoDB")


def get_role_by_arn(
    arn: str,
    fields: Optional[List[str]] = None,
    dynamo_table: Optional[Table] = None,
) -> Dict[str, Any]:
    table = dynamo_table or ROLE_TABLE

    query_input = {
        "IndexName": "Arn",
        "KeyConditionExpression": Key("Arn").eq(arn),
    }

    if fields:
        query_input["ProjectionExpression"] = ", ".join(fields)

    results = table.query(**query_input)
    items = results.get("Items")
    if len(items) < 1:
        raise RoleNotFoundError(f"{arn} not found in DynamoDB")

    if len(items) > 1:
        # multiple results, so we'll grab the first match that's active
        logger.warning("found multiple results for %s in DynamoDB", arn)
        for item in items:
            if item.get("Active", "").lower() == "true":
                return item  # type: ignore

    # we only have one result
    if not isinstance(items[0], dict):
        raise RoleNotFoundError(f"{arn} not found in DynamoDB")
    else:
        return items[0]


def set_role_data(
    role_id: str,
    update_keys: Dict[str, Any],
    dynamo_table: Optional[Table] = None,
    create: bool = False,
) -> None:
    table = dynamo_table or ROLE_TABLE
    if not update_keys:
        return
    if create:
        create_dynamodb_entry(update_keys, dynamo_table)
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
    try:
        table.update_item(
            Key={"RoleId": role_id},
            UpdateExpression=update_expression,
            ExpressionAttributeNames=expression_attribute_names,
            ExpressionAttributeValues=expression_attribute_values,
        )
    except BotoClientError as e:
        error = e.response.get("Error", {})
        code = error.get("Code", "")
        message = error.get("Message", "")
        if code == "ValidationException" and "maximum allowed size" in message:
            raise DynamoDBMaxItemSizeError from e
        else:
            raise DynamoDBError from e


def get_all_role_ids_for_account(
    account_number: str, dynamo_table: Optional[Table] = None
) -> Set[str]:
    """
    Get a set of all role IDs in a given account by querying the Dynamo secondary index 'account'

    Args:
        account_number (string)
        dynamo_table (Table)

    Returns:
        list: role ids in given account
    """
    table = dynamo_table or ROLE_TABLE
    role_ids: Set[str] = set()

    results = table.query(
        IndexName="Account",
        KeyConditionExpression=Key("Account").eq(account_number),
    )
    items = results.get("Items")
    if not items:
        return set()

    role_ids.update([str(return_dict["RoleId"]) for return_dict in items])

    while "LastEvaluatedKey" in results:
        results = table.query(
            IndexName="Account",
            KeyConditionExpression="Account = :act",
            ExpressionAttributeValues={":act": account_number},
            ExclusiveStartKey=results.get("LastEvaluatedKey") or {},
        )
        items = results.get("Items")
        if not items:
            continue
        role_ids.update([str(return_dict["RoleId"]) for return_dict in items])
    return role_ids


def find_role_in_cache(
    role_name: str, account_number: str, dynamo_table: Optional[Table] = None
) -> str:
    """Return role dictionary for active role with name in account

    Args:
        account_number (string)
        role_name (string)
        dynamo_table (Table)

    Returns:
        string: RoleID for active role with name in given account, else None
    """
    table = dynamo_table or ROLE_TABLE
    results = table.query(
        IndexName="RoleName",
        KeyConditionExpression="RoleName = :rn",
        ExpressionAttributeValues={":rn": role_name},
    )
    items = results.get("Items")
    if not items:
        return ""

    role_id_candidates = [str(return_dict["RoleId"]) for return_dict in items]

    if len(role_id_candidates) > 1:
        for role_id in role_id_candidates:
            response = table.get_item(
                Key={"RoleId": role_id}, AttributesToGet=["Account", "Active"]
            )
            item = response.get("Item")
            if item:
                account = item.get("Account")
                active = item.get("Active")
                if active and account == account_number:
                    return role_id
    elif len(role_id_candidates) == 1:
        return role_id_candidates[0]

    return ""


def role_arns_for_all_accounts(dynamo_table: Optional[Table] = None) -> List[str]:
    """
    Get a list of all role IDs for all accounts by scanning the Dynamo table

    Args:
        dynamo_table (Table)

    Returns:
        list: role ids in all accounts
    """
    table = dynamo_table or ROLE_TABLE
    role_ids: List[str] = []

    response = table.scan(ProjectionExpression="Arn")
    role_ids.extend([str(role_dict["Arn"]) for role_dict in response["Items"]])

    while "LastEvaluatedKey" in response:
        response = table.scan(
            ProjectionExpression="Arn",
            ExclusiveStartKey=response["LastEvaluatedKey"],
        )
        role_ids.extend([str(role_dict["Arn"]) for role_dict in response["Items"]])
    return role_ids


dynamodb_config = CONFIG.get("dynamo_db")
if dynamodb_config:
    ROLE_TABLE = dynamo_get_or_create_table(**CONFIG["dynamo_db"])
else:
    logger.warning("No DynamoDB config found; not creating table")
    ROLE_TABLE = None
