import copy
import datetime
from unittest.mock import patch

import pytest

from repokid.exceptions import IntegrityError
from repokid.exceptions import RoleModelError
from repokid.exceptions import RoleNotFoundError
from repokid.role import Role
from repokid.tests import vars


def test_create_role(role_dict):
    r = Role(**role_dict)
    assert r
    assert r.aa_data == vars.aa_data
    assert r.active == vars.active
    assert r.arn == vars.arn
    assert r.assume_role_policy_document == vars.assume_role_policy_document
    assert r.create_date == vars.create_date
    assert r.disqualified_by == vars.disqualified_by
    assert r.last_updated == vars.last_updated
    assert r.no_repo_permissions == vars.no_repo_permissions
    assert r.opt_out == vars.opt_out
    assert r.policies == vars.policies
    assert r.refreshed == vars.refreshed
    assert r.repoable_permissions == vars.repoable_permissions
    assert r.repoable_services == vars.repoable_services
    assert r.repoed == vars.repoed
    assert r.repo_scheduled == vars.repo_scheduled
    assert r.role_id == vars.role_id
    assert r.role_name == vars.role_name
    assert r.scheduled_perms == vars.scheduled_perms
    assert r.stats == vars.stats
    assert r.tags == vars.tags
    assert r.total_permissions == vars.total_permissions


def test_create_role_from_aliases(role_dict_with_aliases):
    r = Role(**role_dict_with_aliases)
    assert r
    assert r.aa_data == vars.aa_data
    assert r.active == vars.active
    assert r.arn == vars.arn
    assert r.assume_role_policy_document == vars.assume_role_policy_document
    assert r.create_date == vars.create_date
    assert r.disqualified_by == vars.disqualified_by
    assert r.last_updated == vars.last_updated
    assert r.no_repo_permissions == vars.no_repo_permissions
    assert r.opt_out == vars.opt_out
    assert r.policies == vars.policies
    assert r.refreshed == vars.refreshed
    assert r.repoable_permissions == vars.repoable_permissions
    assert r.repoable_services == vars.repoable_services
    assert r.repoed == vars.repoed
    assert r.repo_scheduled == vars.repo_scheduled
    assert r.role_id == vars.role_id
    assert r.role_name == vars.role_name
    assert r.scheduled_perms == vars.scheduled_perms
    assert r.stats == vars.stats
    assert r.tags == vars.tags
    assert r.total_permissions == vars.total_permissions


def test_role_update(role_dict):
    r = Role(**role_dict)
    updates = {"repoable_permissions": 20}
    r.update(updates, store=False)
    assert r.repoable_permissions == 20


@patch("repokid.role.get_role_by_id")
@patch("repokid.role.set_role_data")
def test_role_update_store(
    mock_set_role_data, mock_get_role_by_id, role_dict, role_dict_with_aliases
):
    expected = {"RepoablePermissions": 20, "LastUpdated": vars.last_updated}
    mock_get_role_by_id.return_value = {
        "LastUpdated": vars.last_updated.strftime("%Y-%m-%d %H:%M")
    }
    r = Role(**role_dict)
    updates = {"repoable_permissions": 20}
    r.update(updates, store=True)
    assert r.repoable_permissions == 20
    mock_set_role_data.assert_called_once()
    assert mock_set_role_data.call_args[0][0] == r.role_id
    # LastUpdated gets set when we store, so we just need to make sure it's different now
    assert mock_set_role_data.call_args[0][1]["LastUpdated"] > expected["LastUpdated"]

    # Remove LastUpdated from the fn call and expected dict so we can compare the rest
    mock_set_role_data.call_args[0][1].pop("LastUpdated")
    expected.pop("LastUpdated")

    assert mock_set_role_data.call_args[0][1] == expected


def test_role_update_by_alias(role_dict):
    r = Role(**role_dict)
    updates = {"RepoablePermissions": 20}
    r.update(updates, store=False)
    assert r.repoable_permissions == 20


@patch("repokid.role.get_aardvark_data")
def test_role_fetch_aa_data(mock_get_aardvark_data, role_dict):
    mock_get_aardvark_data.return_value = {vars.arn: [{"a": "b"}]}
    r = Role(**role_dict)
    r.fetch_aa_data()
    assert r.aa_data[0]


def test_role_fetch_aa_data_no_arn(role_dict):
    role_data = copy.deepcopy(role_dict)
    role_data.pop("arn")
    r = Role(**role_data)
    with pytest.raises(RoleModelError):
        r.fetch_aa_data()


@patch("repokid.role.get_role_by_id")
def test_role_fetch(mock_get_role_by_id, role_dict):
    stored_role_data = copy.deepcopy(role_dict)
    stored_role_data["repoable_permissions"] = 20
    mock_get_role_by_id.return_value = stored_role_data
    r = Role(**role_dict)
    assert r.repoable_permissions == 5
    r.fetch()
    assert r.repoable_permissions == 20


@patch("repokid.role.get_role_by_name")
def test_role_fetch_no_id(mock_get_role_by_name, role_dict):
    stored_role_data = copy.deepcopy(role_dict)
    stored_role_data["repoable_permissions"] = 20
    mock_get_role_by_name.return_value = stored_role_data
    local_role_data = copy.deepcopy(role_dict)
    local_role_data.pop("role_id")
    r = Role(**local_role_data)
    assert r.repoable_permissions == 5
    r.fetch()
    assert r.repoable_permissions == 20


def test_role_fetch_not_found(role_dict):
    local_role_data = copy.deepcopy(role_dict)
    local_role_data.pop("role_id")
    local_role_data.pop("role_name")
    local_role_data.pop("account")
    r = Role(**local_role_data)
    with pytest.raises(RoleModelError):
        r.fetch()


def test_role_fetch_dirty(role_dict):
    r = Role(**role_dict)
    r._dirty = True
    with pytest.raises(IntegrityError):
        r.fetch()


@patch("repokid.role.get_role_by_id")
@patch("repokid.role.set_role_data")
def test_role_store(
    mock_set_role_data, mock_get_role_by_id, role_dict, role_dict_with_aliases
):
    expected = copy.deepcopy(role_dict_with_aliases)
    expected.pop("RoleId")
    expected.pop("RoleName")
    expected.pop("Account")
    mock_get_role_by_id.return_value = {
        "LastUpdated": vars.last_updated.strftime("%Y-%m-%d %H:%M")
    }
    r = Role(**role_dict)
    r.store()
    mock_set_role_data.assert_called_once()
    assert mock_set_role_data.call_args[0][0] == r.role_id
    # LastUpdated gets set when we store, so we just need to make sure it's different now
    assert mock_set_role_data.call_args[0][1]["LastUpdated"] > expected["LastUpdated"]

    # Remove LastUpdated from the fn call and expected dict so we can compare the rest
    mock_set_role_data.call_args[0][1].pop("LastUpdated")
    expected.pop("LastUpdated")

    assert mock_set_role_data.call_args[0][1] == expected


@patch("repokid.role.get_role_by_id")
@patch("repokid.role.set_role_data")
def test_role_store_fields(
    mock_set_role_data, mock_get_role_by_id, role_dict, role_dict_with_aliases
):
    expected = {"RepoablePermissions": 5, "LastUpdated": vars.last_updated}
    mock_get_role_by_id.return_value = {
        "LastUpdated": vars.last_updated.strftime("%Y-%m-%d %H:%M")
    }
    r = Role(**role_dict)
    r.store(fields=["repoable_permissions"])
    mock_set_role_data.assert_called_once()
    assert mock_set_role_data.call_args[0][0] == r.role_id
    # LastUpdated gets set when we store, so we just need to make sure it's different now
    assert mock_set_role_data.call_args[0][1]["LastUpdated"] > expected["LastUpdated"]

    # Remove LastUpdated from the fn call and expected dict so we can compare the rest
    mock_set_role_data.call_args[0][1].pop("LastUpdated")
    expected.pop("LastUpdated")

    assert mock_set_role_data.call_args[0][1] == expected


@patch("repokid.role.get_role_by_id")
def test_role_store_remote_updated(
    mock_get_role_by_id, role_dict, role_dict_with_aliases
):
    expected = copy.deepcopy(role_dict_with_aliases)
    expected.pop("RoleId")
    expected.pop("RoleName")
    expected.pop("Account")

    # simulate the record having been updated in DynamoDB since we last fetched it
    last_updated = (vars.last_updated + datetime.timedelta(hours=2)).strftime(
        "%Y-%m-%d %H:%M"
    )
    mock_get_role_by_id.return_value = {"LastUpdated": last_updated}
    r = Role(**role_dict)
    with pytest.raises(IntegrityError):
        r.store()


@patch("repokid.role.get_role_by_id")
@patch("repokid.role.create_dynamodb_entry")
def test_role_store_create(
    mock_create_dynamodb_entry, mock_get_role_by_id, role_dict, role_dict_with_aliases
):
    expected = copy.deepcopy(role_dict_with_aliases)
    mock_get_role_by_id.side_effect = RoleNotFoundError
    r = Role(**role_dict)
    r.store()
    mock_create_dynamodb_entry.assert_called_once()

    # Remove LastUpdated from the fn call and expected dict so we can compare the rest
    mock_create_dynamodb_entry.call_args[0][0].pop("LastUpdated")
    expected.pop("LastUpdated")

    assert mock_create_dynamodb_entry.call_args[0][0] == expected


def test_role_update_refreshed(role_dict):
    r = Role(**role_dict)
    old_refreshed = datetime.datetime.strptime(r.refreshed, "%Y-%m-%dT%H:%M:%S.%f")
    r._update_refreshed()
    new_refreshed = datetime.datetime.strptime(r.refreshed, "%Y-%m-%dT%H:%M:%S.%f")
    assert new_refreshed > old_refreshed
