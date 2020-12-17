import logging
from functools import wraps
from typing import Any
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional
from typing import TypeVar
from typing import Union

from botocore.exceptions import ClientError as BotoClientError
from mypy_boto3_dynamodb.service_resource import Table

from repokid.exceptions import RoleNotFoundError
from repokid.role import Role

LOGGER = logging.getLogger("repokid")
# used as a placeholder for empty SID to work around this: https://github.com/aws/aws-sdk-js/issues/833
DYNAMO_EMPTY_STRING = "---DYNAMO-EMPTY-STRING---"
T = TypeVar("T", str, Dict[Any, Any], List[Any])


def catch_boto_error(func: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(func)
    def decorated_func(*args: Any, **kwargs: Any) -> Any:
        try:
            return func(*args, **kwargs)
        except BotoClientError as e:
            LOGGER.error("Dynamo table error: {}".format(e))

    return decorated_func


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
        return Role(**_empty_string_from_dynamo_replace(response["Item"]))
    else:
        raise RoleNotFoundError(f"Role ID {roleID} not found in DynamoDB")


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
