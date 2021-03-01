from unittest.mock import patch

import pytest

from repokid.datasource.iam import IAMDatasource
from repokid.exceptions import NotFoundError


def test_iam_get():
    ds = IAMDatasource()
    arn = "pretend_arn"
    expected = {"a": "b"}
    ds._data = {arn: expected}
    result = ds.get(arn)
    assert result == expected


def test_iam_get_fallback_not_found():
    ds = IAMDatasource()
    arn = "pretend_arn"
    with pytest.raises(NotFoundError):
        _ = ds.get(arn)


@patch("repokid.datasource.iam.IAMDatasource._fetch_account")
def test_iam_seed(mock_fetch_account):
    ds = IAMDatasource()
    arn = "pretend_arn"
    account_number = "123456789012"
    expected = {arn: {"a": "b"}}
    mock_fetch_account.return_value = expected
    ds.seed(account_number)
    mock_fetch_account.assert_called_once()
    assert mock_fetch_account.call_args[0][0] == account_number
    assert ds._data == expected
    # make sure fetched data gets cached
    assert arn in ds._data
    assert ds._data[arn] == {"a": "b"}
