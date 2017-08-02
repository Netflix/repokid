from marshmallow import Schema, fields, post_load

from cloudaux.aws.sts import boto3_cached_conn

from repokid import CONFIG as CONFIG
from repokid import LOGGER as LOGGER


class Message(object):
    def __init__(self, command, account, role_name, requestor=None, reason=None):
        self.command = command
        self.account = account
        self.role_name = role_name
        self.requestor = requestor
        self.reason = reason


class MessageSchema(Schema):
    command = fields.Str(required=True)
    account = fields.Str(required=True)
    role_name = fields.Str(required=True)
    requestor = fields.Str()
    reason = fields.Str()

    @post_load
    def make_message(self, data):
        return Message(**data)


def init_messaging(**config):
    sqs = boto3_cached_conn('sqs', service_type='client', assume_role=config.get('assume_role', None),
                            session_name=config['session_name'], region=config['region'])
    sns = boto3_cached_conn('sns', service_type='client', assume_role=config.get('assume_role', None),
                            session_name=config['session_name'], region=config['region'])
    return sqs, sns


def main():
    # test_message = {'command': 'abc', 'account': 'def', 'role_name': 'ghi'}
    # test_message2 = {'command': 'abc', 'account': 'def', 'role_name': 'ghi', 'requestor': 'jkl', 'reason': 'mno'}
    # test_message3 = {'command': 'abc'}
    # 
    # message_schema = MessageSchema()
    # result = message_schema.load(test_message)
    # import pdb; pdb.set_trace()
    
    # (to_repodkid_sqs, from_repokid_sns) = init_messaging(**CONFIG['reactor'])
    # roledata.dynamo_get_or_create_table(**CONFIG['dynamo_db'])
    # 
    # # loop forever, processing messages and respondin
    # while 1:
    #     message = to_repodkid_sqs.receive_message(QueueUrl=CONFIG['reactor']['to_rr_queue'], MaxNumberOfMessages=1,
    #                                               WaitTimeSeconds=20)
    #     if message:
    #         print message
    #     
    #import pdb; pdb.set_trace()
    #output_message = {"channel": "secops_log", "title": "Test", "message": "Quack!"}
    #from_repokid_sns.publish(TopicArn=CONFIG['reactor']['from_rr_sns'], Message=json.dumps(output_message))


if __name__ == "__main__":
    main()
