import copy
import datetime

from marshmallow import ValidationError
from mock import call, patch
import pytest
import repokid.cli.dispatcher_cli as dispatcher_cli
import repokid.dispatcher as dispatcher


DYNAMO_TABLE = None
MESSAGE = dispatcher_cli.Message(
    "command",
    "account",
    "role",
    "respond_channel",
    respond_user="some_user",
    requestor="a_requestor",
    reason="some_reason",
    selection="some_selection",
)


class TestDispatcherCLI(object):
    def test_message_creation(self):
        test_message = MESSAGE
        assert test_message.command == "command"
        assert test_message.account == "account"
        assert test_message.role_name == "role"
        assert test_message.respond_channel == "respond_channel"
        assert test_message.respond_user == "some_user"
        assert test_message.requestor == "a_requestor"
        assert test_message.reason == "some_reason"
        assert test_message.selection == "some_selection"

    def test_schema(self):
        schema = dispatcher_cli.MessageSchema()

        # happy path
        test_message = {
            "command": "list_repoable_services",
            "account": "123",
            "role_name": "abc",
            "respond_channel": "channel",
            "respond_user": "user",
        }
        result = schema.load(test_message)
        assert result.command == "list_repoable_services"

        # missing required field command
        test_message = {
            "account": "123",
            "role_name": "abc",
            "respond_channel": "channel",
            "respond_user": "user",
        }
        with pytest.raises(ValidationError):
            _ = schema.load(test_message)

    @patch("repokid.utils.dynamo.find_role_in_cache")
    @patch("repokid.utils.dynamo.get_role_data")
    def test_list_repoable_services(self, mock_get_role_data, mock_find_role_in_cache):
        mock_find_role_in_cache.side_effect = [None, "ROLE_ID_A"]

        (success, _) = dispatcher.list_repoable_services(DYNAMO_TABLE, MESSAGE)
        assert not success

        (success, _) = dispatcher.list_repoable_services(DYNAMO_TABLE, MESSAGE)
        assert success

    @patch("repokid.utils.dynamo.find_role_in_cache")
    @patch("repokid.utils.dynamo.get_role_data")
    def test_list_role_rollbacks(self, mock_get_role_data, mock_find_role_in_cache):
        mock_find_role_in_cache.side_effect = [None, "ROLE_ID_A"]

        (success, _) = dispatcher.list_role_rollbacks(DYNAMO_TABLE, MESSAGE)
        assert not success

        (success, _) = dispatcher.list_repoable_services(DYNAMO_TABLE, MESSAGE)
        assert success

    @patch("time.time")
    @patch("repokid.utils.dynamo.find_role_in_cache")
    @patch("repokid.utils.dynamo.get_role_data")
    @patch("repokid.utils.dynamo.set_role_data")
    def test_opt_out(
        self, mock_set_role_data, mock_get_role_data, mock_find_role_in_cache, mock_time
    ):
        mock_find_role_in_cache.side_effect = [None, "ROLE_ID_A"]
        GET_ROLE_DATA_FOR_FIND = {}
        mock_get_role_data.side_effect = [
            GET_ROLE_DATA_FOR_FIND,  # role not found
            GET_ROLE_DATA_FOR_FIND,  # opt out exists
            {"OptOut": {"owner": "somebody", "reason": "because"}},
            GET_ROLE_DATA_FOR_FIND,
            {"OptOut": {}},  # success
        ]

        mock_time.return_value = 0

        current_dt = datetime.datetime.fromtimestamp(0)
        expire_dt = current_dt + datetime.timedelta(90)
        expire_epoch = int((expire_dt - datetime.datetime(1970, 1, 1)).total_seconds())

        bad_message = copy.copy(MESSAGE)
        bad_message.reason = None
        # message missing reason
        (success, _) = dispatcher.opt_out(DYNAMO_TABLE, bad_message)
        assert not success

        # role not found
        (success, _) = dispatcher.opt_out(DYNAMO_TABLE, MESSAGE)
        assert not success

        (success, msg) = dispatcher.opt_out(DYNAMO_TABLE, MESSAGE)
        assert success
        assert mock_set_role_data.mock_calls == [
            call(
                DYNAMO_TABLE,
                "ROLE_ID_A",
                {
                    "OptOut": {
                        "owner": MESSAGE.requestor,
                        "reason": MESSAGE.reason,
                        "expire": expire_epoch,
                    }
                },
            )
        ]
