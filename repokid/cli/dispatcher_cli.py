import contextlib
import inspect
import json

from cloudaux.aws.sts import sts_conn
from marshmallow import fields, post_load, Schema
from repokid import CONFIG
import repokid.dispatcher
import repokid.utils.dynamo as dynamo


class Message(object):
    def __init__(
        self,
        command,
        account,
        role_name,
        respond_channel,
        respond_user=None,
        requestor=None,
        reason=None,
        selection=None,
    ):
        self.command = command
        self.account = account
        self.role_name = role_name
        self.respond_channel = respond_channel
        self.respond_user = respond_user
        self.requestor = requestor
        self.reason = reason
        self.selection = selection


class MessageSchema(Schema):
    command = fields.Str(required=True)
    account = fields.Str(required=True)
    role_name = fields.Str(required=True)
    respond_channel = fields.Str(required=True)
    respond_user = fields.Str()
    requestor = fields.Str()
    reason = fields.Str()
    selection = fields.Str()

    @post_load
    def make_message(self, data, **kwargs):
        return Message(**data)


def get_failure_message(channel=None, message=None):
    return {"channel": channel, "message": message, "title": "Repokid Failure"}


@sts_conn("sqs")
def delete_message(receipt_handle, client=None):
    client.delete_message(
        QueueUrl=CONFIG["dispatcher"]["to_rr_queue"], ReceiptHandle=receipt_handle
    )


@sts_conn("sqs")
def receive_message(client=None):
    return client.receive_message(
        QueueUrl=CONFIG["dispatcher"]["to_rr_queue"],
        MaxNumberOfMessages=1,
        WaitTimeSeconds=10,
    )


@sts_conn("sns")
def send_message(message_dict, client=None):
    client.publish(
        TopicArn=CONFIG["dispatcher"]["from_rr_sns"], Message=json.dumps(message_dict)
    )


@contextlib.contextmanager
def message_context(message_object, connection):
    try:
        receipt_handle = message_object["Messages"][0]["ReceiptHandle"]
        yield json.loads(message_object["Messages"][0]["Body"])
    except KeyError:
        # we might not actually have a message
        yield None
    else:
        if receipt_handle:
            delete_message(receipt_handle, **connection)


all_funcs = inspect.getmembers(repokid.dispatcher, inspect.isfunction)
RESPONDER_FUNCTIONS = {
    func[1]._implements_command: func[1]
    for func in all_funcs
    if hasattr(func[1], "_implements_command")
}


def main():
    dynamo_table = dynamo.dynamo_get_or_create_table(**CONFIG["dynamo_db"])
    message_schema = MessageSchema()

    connection = {
        "assume_role": CONFIG["dispatcher"].get("assume_role", None),
        "session_name": CONFIG["dispatcher"].get("session_name", "Repokid"),
        "region": CONFIG["dispatcher"].get("region", "us-west-2"),
    }

    while True:
        message = receive_message(**connection)
        if not message or "Messages" not in message:
            continue

        with message_context(message, connection) as msg:
            if not msg:
                continue

            parsed_msg = message_schema.load(msg)
            command_data = parsed_msg.data

            if parsed_msg.errors:
                failure_message = get_failure_message(
                    channel=command_data.get("respond_channel", None),
                    message="Malformed message: {}".format(parsed_msg.errors),
                )
                send_message(failure_message, **connection)
                continue

            try:
                return_val = RESPONDER_FUNCTIONS[command_data.command](
                    dynamo_table, command_data
                )
            except KeyError:
                failure_message = get_failure_message(
                    channel=command_data.respond_channel,
                    message="Unknown function {}".format(command_data.command),
                )
                send_message(failure_message, **connection)
                continue

            send_message(
                {
                    "message": "@{} {}".format(
                        command_data.respond_user, return_val.return_message
                    ),
                    "channel": command_data.respond_channel,
                    "title": "Repokid Success"
                    if return_val.successful
                    else "Repokid Failure",
                },
                **connection
            )


if __name__ == "__main__":
    main()
