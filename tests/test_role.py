#  Copyright 2020 Netflix, Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import copy
import datetime
from unittest.mock import patch

import pytest
from dateutil.parser import parse as ts_parse

from repokid.exceptions import IntegrityError
from repokid.exceptions import MissingRepoableServices
from repokid.exceptions import ModelError
from repokid.exceptions import RoleNotFoundError
from repokid.role import Role
from tests import vars


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


@patch("repokid.role.Role._calculate_no_repo_permissions")
@patch("repokid.role.Role.store")
def test_role_add_policy_version(
    mock_store, mock_calculate_no_repo_permissions, role_dict
):
    r = Role(**role_dict)
    source = "Test"
    fake_policy = {"what_do": "everything"}
    assert len(r.policies) == 1
    r.add_policy_version(fake_policy, source=source, store=True)
    assert len(r.policies) == 2
    assert r.policies[1]["Source"] == source
    assert r.policies[1]["Policy"] == fake_policy
    mock_calculate_no_repo_permissions.assert_called_once()
    mock_store.assert_called_once()
    assert mock_store.call_args[1]["fields"] == ["Policies", "NoRepoPermissions"]


@patch("repokid.role.Role._calculate_no_repo_permissions")
@patch("repokid.role.Role.store")
def test_role_add_policy_version_duplicate(
    mock_store, mock_calculate_no_repo_permissions, role_dict
):
    r = Role(**role_dict)
    source = "Fixture"
    fake_policy = vars.policies[0]["Policy"]
    assert len(r.policies) == 1
    r.add_policy_version(fake_policy, source=source, store=True)
    assert len(r.policies) == 1
    assert r.policies[0]["Policy"] == fake_policy
    mock_calculate_no_repo_permissions.assert_not_called()
    mock_store.assert_not_called()


@patch("repokid.role.convert_repoable_perms_to_perms_and_services")
@patch("repokid.role.get_repoable_permissions")
@patch("repokid.role.Role.get_permissions_for_policy_version")
def test_role_calculate_repo_scores(
    mock_get_permissions_for_policy_version,
    mock_get_repoable_permissions,
    mock_convert_repoable_perms_to_perms_and_services,
    role_dict,
):
    mock_get_permissions_for_policy_version.return_value = (
        {"service1:action1", "service1:action2", "service2", "service3:action3"},
        {"service1:action2", "service2", "service3:action3"},
    )
    mock_get_repoable_permissions.return_value = {"service1:action2", "service2"}
    mock_convert_repoable_perms_to_perms_and_services.return_value = (
        {"service1:action2"},
        {"service2"},
    )

    r = Role(**role_dict)
    r.calculate_repo_scores(0, {})

    mock_get_permissions_for_policy_version.assert_called_once()
    mock_get_repoable_permissions.assert_called_once()
    mock_convert_repoable_perms_to_perms_and_services.assert_called_once()
    assert r.total_permissions == 4
    assert r.repoable_services == ["service1:action2", "service2"]
    assert r.repoable_permissions == 2


@patch("repokid.role.convert_repoable_perms_to_perms_and_services")
@patch("repokid.role.get_repoable_permissions")
@patch("repokid.role.Role.get_permissions_for_policy_version")
def test_role_calculate_repo_scores_disqualified(
    mock_get_permissions_for_policy_version,
    mock_get_repoable_permissions,
    mock_convert_repoable_perms_to_perms_and_services,
    role_dict,
):
    mock_get_permissions_for_policy_version.return_value = (
        {"service1:action1", "service1:action2", "service2", "service3:action3"},
        {"service1:action2", "service2", "service3:action3"},
    )

    r = Role(**role_dict)
    r.disqualified_by = ["a filter"]
    r.calculate_repo_scores(0, {})

    mock_get_permissions_for_policy_version.assert_called_once()
    mock_get_repoable_permissions.assert_not_called()
    mock_convert_repoable_perms_to_perms_and_services.assert_not_called()
    assert r.total_permissions == 4
    assert r.repoable_services == []
    assert r.repoable_permissions == 0


@patch("repokid.role.convert_repoable_perms_to_perms_and_services")
@patch("repokid.role.get_repoable_permissions")
@patch("repokid.role.Role.get_permissions_for_policy_version")
def test_role_calculate_repo_scores_no_aa_data(
    mock_get_permissions_for_policy_version,
    mock_get_repoable_permissions,
    mock_convert_repoable_perms_to_perms_and_services,
    role_dict,
):
    mock_get_permissions_for_policy_version.return_value = (
        {"service1:action1", "service1:action2", "service2", "service3:action3"},
        {"service1:action2", "service2", "service3:action3"},
    )

    r = Role(**role_dict)
    r.aa_data = []
    r.calculate_repo_scores(0, {})

    mock_get_permissions_for_policy_version.assert_called_once()
    mock_get_repoable_permissions.assert_not_called()
    mock_convert_repoable_perms_to_perms_and_services.assert_not_called()
    assert r.total_permissions == 4
    assert r.repoable_services == []
    assert r.repoable_permissions == 0


@patch("repokid.role.get_permissions_in_policy")
def test_role_get_permissions_for_policy_version(
    mock_get_permissions_in_policy, role_dict
):
    r = Role(**role_dict)
    r.get_permissions_for_policy_version()

    mock_get_permissions_in_policy.assert_called_once()
    assert mock_get_permissions_in_policy.call_args[0][0] == vars.policies[-1]["Policy"]
    assert not mock_get_permissions_in_policy.call_args[1]["warn_unknown_perms"]


@patch("repokid.role.get_permissions_in_policy")
def test_role_get_permissions_for_policy_version_no_policies(
    mock_get_permissions_in_policy, role_dict
):
    r = Role(**role_dict)
    r.policies = {}
    r.get_permissions_for_policy_version()

    mock_get_permissions_in_policy.assert_not_called()


@patch("repokid.role.find_newly_added_permissions")
def test_role_calculate_no_repo_permissions(
    mock_find_newly_added_permissions, role_dict
):
    mock_find_newly_added_permissions.return_value = {
        "service1:action1",
        "service1:action2",
        "service2:action3",
    }
    r = Role(**role_dict)
    r._calculate_no_repo_permissions()
    mock_find_newly_added_permissions.assert_called_once()
    assert mock_find_newly_added_permissions.call_args[0][0] == {}
    assert (
        mock_find_newly_added_permissions.call_args[0][1] == vars.policies[-1]["Policy"]
    )
    assert "service3:action4" not in r.no_repo_permissions
    assert "service1:action1" in r.no_repo_permissions
    assert "service1:action2" in r.no_repo_permissions
    assert "service2:action3" in r.no_repo_permissions
    assert r.no_repo_permissions["service1:action1"] > 0
    assert r.no_repo_permissions["service1:action2"] > 0
    assert r.no_repo_permissions["service2:action3"] > 0


@patch("repokid.role.get_repoed_policy")
@patch("repokid.role.get_services_and_permissions_from_repoable")
def test_role_get_repoed_policy(
    mock_get_services_and_permissions_from_repoable, mock_get_repoed_policy, role_dict
):
    mock_get_repoed_policy.return_value = ({"repoed": "woohoo"}, ["old_policy_name"])
    r = Role(**role_dict)
    repoed_policies, deleted_policy_names = r.get_repoed_policy(scheduled=False)
    mock_get_repoed_policy.assert_called_once()
    mock_get_services_and_permissions_from_repoable.assert_not_called()
    assert mock_get_repoed_policy.call_args[0][0] == vars.policies[-1]["Policy"]
    assert mock_get_repoed_policy.call_args[0][1] == set(vars.repoable_services)
    assert repoed_policies == {"repoed": "woohoo"}
    assert deleted_policy_names == ["old_policy_name"]


@patch("repokid.role.get_repoed_policy")
@patch("repokid.role.get_services_and_permissions_from_repoable")
def test_role_get_repoed_policy_scheduled(
    mock_get_services_and_permissions_from_repoable, mock_get_repoed_policy, role_dict
):
    mock_get_repoed_policy.return_value = ({"repoed": "woohoo"}, ["old_policy_name"])
    mock_get_services_and_permissions_from_repoable.return_value = (
        {"service1:action1", "service1:action2", "service2:action3"},
        {"service3"},
    )
    r = Role(**role_dict)
    r.scheduled_perms = ["service1:action1"]
    repoed_policies, deleted_policy_names = r.get_repoed_policy(scheduled=True)
    mock_get_services_and_permissions_from_repoable.assert_called_once()
    mock_get_repoed_policy.assert_called_once()
    assert mock_get_repoed_policy.call_args[0][0] == vars.policies[-1]["Policy"]
    assert mock_get_repoed_policy.call_args[0][1] == {"service3", "service1:action1"}
    assert repoed_policies == {"repoed": "woohoo"}
    assert deleted_policy_names == ["old_policy_name"]


@patch("repokid.role.get_repoed_policy")
@patch("repokid.role.get_services_and_permissions_from_repoable")
def test_role_get_repoed_policy_no_repoable_services(
    mock_get_services_and_permissions_from_repoable, mock_get_repoed_policy, role_dict
):
    r = Role(**role_dict)
    r.repoable_services = []
    with pytest.raises(MissingRepoableServices):
        r.get_repoed_policy()
    mock_get_repoed_policy.assert_not_called()
    mock_get_services_and_permissions_from_repoable.assert_not_called()


@patch("repokid.role.Role._stale_aa_services")
def test_role_is_eligible_for_repo(mock_stale_aa_services, role_dict):
    mock_stale_aa_services.return_value = []
    r = Role(**role_dict)
    eligible, reason = r.is_eligible_for_repo()
    mock_stale_aa_services.assert_called_once()
    assert eligible
    assert not reason


@patch("repokid.role.Role._stale_aa_services")
def test_role_is_eligible_for_repo_disqualified(mock_stale_aa_services, role_dict):
    r = Role(**role_dict)
    r.disqualified_by = ["filter1", "filter2"]
    eligible, reason = r.is_eligible_for_repo()
    mock_stale_aa_services.assert_not_called()
    assert not eligible
    assert reason == "disqualified by filter1, filter2"


@patch("repokid.role.Role._stale_aa_services")
def test_role_is_eligible_for_repo_no_aa_data(mock_stale_aa_services, role_dict):
    r = Role(**role_dict)
    r.aa_data = []
    eligible, reason = r.is_eligible_for_repo()
    mock_stale_aa_services.assert_not_called()
    assert not eligible
    assert reason == "no Access Advisor data available"


@patch("repokid.role.Role._stale_aa_services")
def test_role_is_eligible_for_repo_no_repoable_permissions(
    mock_stale_aa_services, role_dict
):
    r = Role(**role_dict)
    r.repoable_permissions = []
    r.scheduled_perms = []
    eligible, reason = r.is_eligible_for_repo()
    mock_stale_aa_services.assert_not_called()
    assert not eligible
    assert reason == "no repoable permissions"


@patch("repokid.role.Role._stale_aa_services")
def test_role_is_eligible_for_repo_stale_aa_data(mock_stale_aa_services, role_dict):
    mock_stale_aa_services.return_value = ["service1", "service2"]
    r = Role(**role_dict)
    eligible, reason = r.is_eligible_for_repo()
    mock_stale_aa_services.assert_called_once()
    assert not eligible
    assert reason == "stale Access Advisor data for service1, service2"


def test_role_stale_aa_services(role_dict):
    r = Role(**role_dict)
    r.config["repo_requirements"] = {"oldest_aa_data_days": 5}
    recent_dt = datetime.datetime.now() - datetime.timedelta(days=1)
    older_dt = datetime.datetime.now() - datetime.timedelta(days=14)

    r.aa_data = [
        {"serviceName": "service1", "lastUpdated": recent_dt.isoformat()},
        {"serviceName": "service2", "lastUpdated": recent_dt.isoformat()},
        {"serviceName": "service3", "lastUpdated": older_dt.isoformat()},
        {"serviceName": "service4", "lastUpdated": older_dt.isoformat()},
    ]
    stale = r._stale_aa_services()
    assert "service1" not in stale
    assert "service2" not in stale
    assert "service3" in stale
    assert "service4" in stale


def test_role_stale_aa_services_no_aa_data(role_dict):
    r = Role(**role_dict)
    r.config["repo_requirements"] = {"oldest_aa_data_days": 5}
    r.aa_data = []
    stale = r._stale_aa_services()
    assert len(stale) == 0


def test_role_update_opt_out(role_dict):
    r = Role(**role_dict)
    recent_dt = datetime.datetime.now() - datetime.timedelta(days=1)
    r.opt_out = {"expire": recent_dt.timestamp()}
    r._update_opt_out()
    assert r.opt_out == {}


def test_role_update_opt_out_future(role_dict):
    r = Role(**role_dict)
    future_dt = datetime.datetime.now() + datetime.timedelta(days=1)
    r.opt_out = {"expire": future_dt.timestamp()}
    r._update_opt_out()
    # opt out should not have been touched since it is not expired
    assert r.opt_out == {"expire": future_dt.timestamp()}


@patch("repokid.role.Role.store")
def test_role_mark_inactive(mock_store, role_dict):
    r = Role(**role_dict)
    r.active = True
    r.mark_inactive(store=True)
    assert not r.active
    mock_store.assert_called_once()
    assert mock_store.call_args[1]["fields"] == ["active"]


@patch("repokid.role.Role.store")
def test_role_mark_inactive_no_store(mock_store, role_dict):
    r = Role(**role_dict)
    r.active = True
    r.mark_inactive()
    assert not r.active
    mock_store.assert_not_called()


def test_role_update(role_dict):
    r = Role(**role_dict)
    updates = {"repoable_permissions": 20}
    r.update(updates, store=False)
    assert r.repoable_permissions == 20


@patch("repokid.role.get_role_by_id")
@patch("repokid.role.set_role_data")
def test_role_update_store(mock_set_role_data, mock_get_role_by_id, role_dict):
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


@patch("repokid.role.AccessAdvisorDatasource.get")
@patch("repokid.role.AccessAdvisorDatasource.seed")
def test_role_fetch_aa_data(mock_seed_aardvark_data, mock_get_aardvark_data, role_dict):
    mock_get_aardvark_data.return_value = [{"a": "b"}]
    r = Role(**role_dict)
    r.fetch_aa_data()
    assert r.aa_data[0]


def test_role_fetch_aa_data_no_arn(role_dict):
    role_data = copy.deepcopy(role_dict)
    role_data.pop("arn")
    role_data.pop("account")
    r = Role(**role_data)
    with pytest.raises(ModelError):
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


@patch("repokid.role.get_role_by_arn")
def test_role_fetch_no_id(mock_get_role_by_arn, role_dict):
    stored_role_data = copy.deepcopy(role_dict)
    stored_role_data["repoable_permissions"] = 20
    mock_get_role_by_arn.return_value = stored_role_data
    local_role_data = copy.deepcopy(role_dict)
    local_role_data.pop("role_id")
    r = Role(**local_role_data)
    assert r.repoable_permissions == 5
    r.fetch()
    assert r.repoable_permissions == 20


@patch("repokid.role.get_role_by_arn")
def test_role_fetch_not_found(mock_get_role_by_arn, role_dict):
    mock_get_role_by_arn.side_effect = RoleNotFoundError
    local_role_data = copy.deepcopy(role_dict)
    local_role_data.pop("role_id")
    local_role_data.pop("role_name")
    local_role_data.pop("account")
    r = Role(**local_role_data)
    with pytest.raises(RoleNotFoundError):
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
@patch("repokid.utils.dynamo.create_dynamodb_entry")
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
    old_refreshed = ts_parse(r.refreshed)
    r._update_refreshed()
    new_refreshed = ts_parse(r.refreshed)
    assert new_refreshed > old_refreshed
