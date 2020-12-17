import datetime

aa_data = [{}]
account = "123456789012"
active = True
arn = f"arn:aws:iam:{account}::role/TestRole"
assume_role_policy_document = {}
create_date = datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(
    days=10
)
disqualified_by = [""]
last_updated = datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(
    hours=2
)
no_repo_permissions = {}
opt_out = {}
policies = [{}]
refreshed = (
    datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(hours=1)
).isoformat()
repoable_permissions = 5
repoable_services = [""]
repoed = ""
repo_scheduled = 0.0
role_id = "ARIOABC123BLAHBLAHBLAH"
role_name = "TestRole"
scheduled_perms = {""}
stats = [{}]
tags = [{}]
total_permissions = 5
