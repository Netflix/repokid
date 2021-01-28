from typing import List

import pytest

from repokid.datasource.access_advisor import AccessAdvisorDatasource
from repokid.datasource.iam import ConfigDatasource
from repokid.datasource.iam import IAMDatasource
from repokid.datasource.plugin import DatasourcePlugin


@pytest.fixture(autouse=True)
def purge_datasources():
    datasources: List[DatasourcePlugin] = [
        AccessAdvisorDatasource(),
        IAMDatasource(),
        ConfigDatasource(),
    ]

    for ds in datasources:
        ds.reset()
    yield
    for ds in datasources:
        ds.reset()
