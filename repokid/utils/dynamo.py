import copy
import datetime
import logging
from functools import wraps
from typing import Any
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional
from typing import Set
from typing import Union

import boto3
from botocore.exceptions import ClientError as BotoClientError
from cloudaux.aws.sts import boto3_cached_conn as boto3_cached_conn
from mypy_boto3_dynamodb.service_resource import Table
from mypy_boto3_dynamodb.type_defs import GlobalSecondaryIndexTypeDef

from repokid.exceptions import RoleNotFoundError
from repokid.role import Role

LOGGER = logging.getLogger("repokid")
# used as a placeholder for empty SID to work around this: https://github.com/aws/aws-sdk-js/issues/833
DYNAMO_EMPTY_STRING = "---DYNAMO-EMPTY-STRING---"


def catch_boto_error(func: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(func)
    def decorated_func(*args: Any, **kwargs: Any) -> Any:
        try:
            return func(*args, **kwargs)
        except BotoClientError as e:
            LOGGER.error("Dynamo table error: {}".format(e))

    return decorated_func


@catch_boto_error
def add_to_end_of_list(
    dynamo_table: Table,
    role_id: str,
    field_name: str,
    object_to_add: Dict[str, Any],
    max_retries: int = 5,
    _retries: int = 0,
) -> None:
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


def find_role_in_cache(dynamo_table: Table, account_number: str, role_name: str) -> str:
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
    items = results.get("Items")
    if not items:
        return ""

    role_id_candidates = [str(return_dict["RoleId"]) for return_dict in items]

    if len(role_id_candidates) > 1:
        for role_id in role_id_candidates:
            try:
                role_data = get_role_data(
                    dynamo_table, role_id, fields=["Account", "Active"]
                )
            except RoleNotFoundError as e:
                LOGGER.debug(e)
                continue
            if role_data.account == account_number and role_data.active:
                return role_id
    elif len(role_id_candidates) == 1:
        return role_id_candidates[0]

    return ""


@catch_boto_error
def get_role_data(
    dynamo_table: Table, roleID: str, fields: Optional[List[str]] = None
) -> Role:
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
        return Role.parse_obj(_empty_string_from_dynamo_replace(response["Item"]))
    else:
        raise RoleNotFoundError(f"Role ID {roleID} not found in DynamoDB")


@catch_boto_error
def role_ids_for_account(dynamo_table: Table, account_number: str) -> Set[str]:
    """
    Get a list of all role IDs in a given account by querying the Dynamo secondary index 'account'

    Args:
        account_number (string)

    Returns:
        list: role ids in given account
    """
    role_ids: Set[str] = set()

    results = dynamo_table.query(
        IndexName="Account",
        KeyConditionExpression="Account = :act",
        ExpressionAttributeValues={":act": account_number},
    )
    items = results.get("Items")
    if not items:
        return set()

    role_ids.update([str(return_dict["RoleId"]) for return_dict in items])

    while "LastEvaluatedKey" in results:
        results = dynamo_table.query(
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


@catch_boto_error
def role_ids_for_all_accounts(dynamo_table: Table) -> List[str]:
    """
    Get a list of all role IDs for all accounts by scanning the Dynamo table

    Args:
        None

    Returns:
        list: role ids in all accounts
    """
    role_ids: List[str] = []

    response = dynamo_table.scan(ProjectionExpression="RoleId")
    role_ids.extend([str(role_dict["RoleId"]) for role_dict in response["Items"]])

    while "LastEvaluatedKey" in response:
        response = dynamo_table.scan(
            ProjectionExpression="RoleId",
            ExclusiveStartKey=response["LastEvaluatedKey"],
        )
        role_ids.extend([str(role_dict["RoleId"]) for role_dict in response["Items"]])
    return role_ids


@catch_boto_error
def set_role_data(
    dynamo_table: Table, role_id: str, update_keys: Dict[str, Any]
) -> None:
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
    dynamo_table.update_item(
        Key={"RoleId": role_id},
        UpdateExpression=update_expression,
        ExpressionAttributeNames=expression_attribute_names,
        ExpressionAttributeValues=expression_attribute_values,
    )


# TODO(psanders): should this return a Role object instead of a dict?
def store_initial_role_data(
    dynamo_table: Table,
    arn: str,
    create_date: Optional[datetime.datetime],
    role_id: str,
    role_name: str,
    account_number: str,
    current_policy: Dict[str, Any],
    tags: List[Dict[str, Any]],
) -> Dict[str, Any]:
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

    role_dict: Dict[str, Any] = {
        "Arn": arn,
        "CreateDate": create_date.isoformat() if create_date else "",
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
    item = dict(_empty_string_to_dynamo_replace(store_dynamo))

    dynamo_table.put_item(Item=item)
    # we want to store CreateDate as a string but keep it as a datetime, so put it back here
    role_dict["CreateDate"] = create_date
    return role_dict


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
