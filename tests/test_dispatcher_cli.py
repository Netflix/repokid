import copy

import pytest
from mock import call
from mock import patch
from pydantic.error_wrappers import ValidationError

import repokid.dispatcher as dispatcher
from repokid.dispatcher.types import Message

MESSAGE = Message(
    command="command",
    account="account",
    role_name="role",
    respond_channel="respond_channel",
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

        # happy path
        test_message = {
            "command": "list_repoable_services",
            "account": "123",
            "role_name": "abc",
            "respond_channel": "channel",
            "respond_user": "user",
        }
        result = Message.parse_obj(test_message)
        assert result.command == "list_repoable_services"

        # missing required field command
        test_message = {
            "account": "123",
            "role_name": "abc",
            "respond_channel": "channel",
            "respond_user": "user",
        }
        with pytest.raises(ValidationError):
            _ = Message.parse_obj(test_message)

    @patch("repokid.dispatcher.get_services_and_permissions_from_repoable")
    @patch("repokid.role.Role.fetch")
    @patch("repokid.dispatcher.find_role_in_cache")
    def test_list_repoable_services(
        self,
        mock_find_role_in_cache,
        mock_role_fetch,
        mock_get_services_and_permissions_from_repoable,
    ):
        mock_find_role_in_cache.side_effect = [None, "ROLE_ID_A"]
        mock_get_services_and_permissions_from_repoable.return_value = {"foo", "bar"}

        success, _ = dispatcher.list_repoable_services(MESSAGE)
        assert not success
        mock_find_role_in_cache.assert_called_once()
        mock_role_fetch.assert_not_called()
        mock_get_services_and_permissions_from_repoable.assert_not_called()

        mock_role_fetch.reset_mock()
        mock_get_services_and_permissions_from_repoable.reset_mock()
        mock_find_role_in_cache.reset_mock()

        success, _ = dispatcher.list_repoable_services(MESSAGE)
        assert success
        mock_find_role_in_cache.assert_called_once()
        mock_role_fetch.assert_called_once()
        mock_get_services_and_permissions_from_repoable.assert_called_once()

    @patch("repokid.role.Role.fetch")
    @patch("repokid.dispatcher.find_role_in_cache")
    def test_list_role_rollbacks(self, mock_find_role_in_cache, mock_role_fetch):
        mock_find_role_in_cache.side_effect = [None, "ROLE_ID_A"]

        (success, _) = dispatcher.list_role_rollbacks(MESSAGE)
        assert not success
        mock_find_role_in_cache.assert_called_once()
        mock_role_fetch.assert_not_called()

        mock_role_fetch.reset_mock()
        mock_find_role_in_cache.reset_mock()

        (success, _) = dispatcher.list_repoable_services(MESSAGE)
        assert success
        mock_find_role_in_cache.assert_called_once()
        mock_role_fetch.assert_called_once()

    @patch("time.time")
    @patch("repokid.role.Role.store")
    @patch("repokid.role.Role.fetch")
    @patch("repokid.dispatcher.find_role_in_cache")
    def test_opt_out(
        self, mock_find_role_in_cache, mock_role_fetch, mock_role_store, mock_time
    ):
        mock_find_role_in_cache.side_effect = [None, "ROLE_ID_A"]

        # mock_get_role_data.side_effect = [
        #     MockRoleNoOptOut(),  # role not found
        #     MockRoleNoOptOut(),  # opt out exists
        #     MockRoleOptOut(),
        #     MockRoleNoOptOut(),
        #     MockRoleEmptyOptOut(),  # success
        # ]

        mock_time.return_value = 0

        bad_message = copy.deepcopy(MESSAGE)
        bad_message.reason = None
        # message missing reason
        (success, _) = dispatcher.opt_out(bad_message)
        assert not success

        # role not found
        (success, _) = dispatcher.opt_out(MESSAGE)
        assert not success

        (success, msg) = dispatcher.opt_out(MESSAGE)
        assert success
        assert mock_role_store.mock_calls[0] == call(fields=["opt_out"])
