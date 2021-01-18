from unittest.mock import patch

import pytest

from repokid.datasource.access_advisor import AccessAdvisorDatasource
from repokid.exceptions import NotFoundError


def test_access_advisor_get():
    ds = AccessAdvisorDatasource()
    arn = "pretend_arn"
    expected = [{"a": "b"}]
    ds._data = {arn: expected}
    result = ds.get(arn)
    assert result == expected


@patch("repokid.datasource.access_advisor.AccessAdvisorDatasource._fetch")
def test_access_advisor_get_fallback(mock_fetch):
    ds = AccessAdvisorDatasource()
    arn = "pretend_arn"
    expected = [{"a": "b"}]
    mock_fetch.return_value = {arn: expected}
    result = ds.get(arn)
    mock_fetch.assert_called_once()
    assert mock_fetch.call_args[1]["arn"] == arn
    assert result == expected
    # make sure fetched data gets cached
    assert arn in ds._data
    assert ds._data[arn] == expected


@patch("repokid.datasource.access_advisor.AccessAdvisorDatasource._fetch")
def test_access_advisor_get_fallback_not_found(mock_fetch):
    ds = AccessAdvisorDatasource()
    arn = "pretend_arn"
    mock_fetch.return_value = {}
    with pytest.raises(NotFoundError):
        _ = ds.get(arn)
    mock_fetch.assert_called_once()
    assert mock_fetch.call_args[1]["arn"] == arn


@patch("repokid.datasource.access_advisor.AccessAdvisorDatasource._fetch")
def test_access_advisor_seed(mock_fetch):
    ds = AccessAdvisorDatasource()
    arn = "pretend_arn"
    account_number = "123456789012"
    expected = {arn: [{"a": "b"}]}
    mock_fetch.return_value = expected
    ds.seed(account_number)
    mock_fetch.assert_called_once()
    assert mock_fetch.call_args[1]["account_number"] == account_number
    assert ds._data == expected
    # make sure fetched data gets cached
    assert arn in ds._data
    assert ds._data[arn] == [{"a": "b"}]
