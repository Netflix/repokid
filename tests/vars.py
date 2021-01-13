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

import datetime

sample_aa_service = {
    "lastUpdated": "Thu, 17 Dec 2020 02:01:36 GMT",
    "lastAuthenticatedEntity": None,
    "serviceNamespace": "test",
    "serviceName": "AWS Test Service",
    "totalAuthenticatedEntities": 0,
    "lastAuthenticated": 0,
}

aa_data = [sample_aa_service]
account = "123456789012"
active = True
arn = f"arn:aws:iam:{account}::role/TestRole"
assume_role_policy_document = {}
create_date = datetime.datetime.now() - datetime.timedelta(days=10)
disqualified_by = []
last_updated = datetime.datetime.now() - datetime.timedelta(hours=2)
no_repo_permissions = {"service3:action4": 0}
opt_out = {}
policies = [{"Policy": {"this_is_fake": "cool"}, "Source": "Fixture"}]
refreshed = (datetime.datetime.now() - datetime.timedelta(hours=1)).isoformat()
repoable_permissions = 5
repoable_services = [
    "service1:action1",
    "service1:action2",
    "service2:action3",
    "service3",
]
repoed = ""
repo_scheduled = 0.0
role_id = "ARIOABC123BLAHBLAHBLAH"
role_name = "TestRole"
scheduled_perms = [""]
stats = [{}]
tags = [{}]
total_permissions = 5
