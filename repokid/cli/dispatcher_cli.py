import contextlib
import inspect
import json
from typing import Any
from typing import Dict
from typing import Generator
from typing import Optional

from cloudaux.aws.sts import boto3_cached_conn
from mypy_boto3_sns.client import SNSClient
from mypy_boto3_sqs.client import SQSClient
from mypy_boto3_sqs.type_defs import ReceiveMessageResultTypeDef

import repokid.dispatcher
from repokid import CONFIG
from repokid.dispatcher.types import Message


def get_failure_message(channel: str, message: str) -> Dict[str, Any]:
    return {"channel": channel, "message": message, "title": "Repokid Failure"}


def delete_message(receipt_handle: str, conn_details: Dict[str, Any]) -> None:
    client: SQSClient = boto3_cached_conn("sqs", **conn_details)
    client.delete_message(
        QueueUrl=CONFIG["dispatcher"]["to_rr_queue"], ReceiptHandle=receipt_handle
    )


def receive_message(conn_details: Dict[str, Any]) -> ReceiveMessageResultTypeDef:
    client: SQSClient = boto3_cached_conn("sqs", **conn_details)
    return client.receive_message(
        QueueUrl=CONFIG["dispatcher"]["to_rr_queue"],
        MaxNumberOfMessages=1,
        WaitTimeSeconds=10,
    )


def send_message(message_dict: Dict[str, Any], conn_details: Dict[str, Any]) -> None:
    client: SNSClient = boto3_cached_conn("sns", **conn_details)
    client.publish(
        TopicArn=CONFIG["dispatcher"]["from_rr_sns"], Message=json.dumps(message_dict)
    )


@contextlib.contextmanager
def message_context(
    message_object: ReceiveMessageResultTypeDef, connection: Dict[str, Any]
) -> Generator[Optional[str], Dict[str, Any], None]:
    try:
        receipt_handle = message_object["Messages"][0]["ReceiptHandle"]
        yield json.loads(message_object["Messages"][0]["Body"])
    except KeyError:
        # we might not actually have a message
        yield None
    else:
        if receipt_handle:
            delete_message(receipt_handle, connection)


all_funcs = inspect.getmembers(repokid.dispatcher, inspect.isfunction)
RESPONDER_FUNCTIONS = {
    func[1]._implements_command: func[1]
    for func in all_funcs
    if hasattr(func[1], "_implements_command")
}


def main() -> None:
    conn_details = {
        "assume_role": CONFIG["dispatcher"].get("assume_role", None),
        "session_name": CONFIG["dispatcher"].get("session_name", "Repokid"),
        "region": CONFIG["dispatcher"].get("region", "us-west-2"),
    }

    while True:
        message = receive_message(conn_details)
        if not message or "Messages" not in message:
            continue

        with message_context(message, conn_details) as msg:
            if not msg:
                continue

            parsed_msg = Message.parse_obj(msg)

            if parsed_msg.errors:
                failure_message = get_failure_message(
                    channel=parsed_msg.respond_channel,
                    message="Malformed message: {}".format(parsed_msg.errors),
                )
                send_message(failure_message, conn_details)
                continue

            try:
                return_val = RESPONDER_FUNCTIONS[parsed_msg.command](parsed_msg)
            except KeyError:
                failure_message = get_failure_message(
                    channel=parsed_msg.respond_channel,
                    message="Unknown function {}".format(parsed_msg.command),
                )
                send_message(failure_message, conn_details)
                continue

            send_message(
                {
                    "message": "@{} {}".format(
                        parsed_msg.respond_user, return_val.return_message
                    ),
                    "channel": parsed_msg.respond_channel,
                    "title": "Repokid Success"
                    if return_val.successful
                    else "Repokid Failure",
                },
                conn_details,
            )


if __name__ == "__main__":
    main()
