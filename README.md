Repokid
=======
[![NetflixOSS Lifecycle](https://img.shields.io/osslifecycle/Netflix/osstracker.svg)]()
[![Build Status](https://travis-ci.com/Netflix/repokid.svg?branch=master)](https://travis-ci.com/Netflix/repokid)
[![Coverage Status](https://coveralls.io/repos/github/Netflix/repokid/badge.svg?branch=master)](https://coveralls.io/github/Netflix/repokid?branch=master)
[![Discord chat](https://img.shields.io/discord/754080763070382130?logo=discord)](https://discord.gg/9kwMWa6)

<img align="center" alt="Repokid Logo" src="docs/images/Repokid.png" width="25%" display="block">

Repokid uses Access Advisor provided by [Aardvark](https://github.com/Netflix-Skunkworks/aardvark)
to remove permissions granting access to unused services from the inline policies of IAM roles in
an AWS account.

## Getting Started

### Install

```bash
mkvirtualenv repokid
git clone git@github.com:Netflix/repokid.git
cd repokid
pip install -e .
repokid config config.json
```

#### DynamoDB

You will need a [DynamoDB](https://aws.amazon.com/dynamodb/) table called `repokid_roles` (specify account and endpoint in `dynamo_db` in config file).

The table should have the following properties:
 - `RoleId` (string) as a primary partition key, no primary sort key
 - A global secondary index named `Account` with a primary partition key of `Account` and `RoleId` and `Account` as projected attributes
 - A global secondary index named `RoleName` with a primary partition key of `RoleName` and `RoleId` and `RoleName` as projected attributes

For development, you can run dynamo [locally](http://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DynamoDBLocal.html).

To run locally:

```bash
docker-compose up
```

The endpoint for DynamoDB will be `http://localhost:8000`. A DynamoDB admin panel can be found at `http://localhost:8001`.

If you run the development version the table and index will be created for you automatically.

#### IAM Permissions

Repokid needs an IAM Role in each account that will be queried.  Additionally, Repokid needs to be launched with a role or user which can `sts:AssumeRole` into the different account roles.

RepokidInstanceProfile:
- Only create one.
- Needs the ability to call `sts:AssumeRole` into all of the RepokidRoles.
- DynamoDB permissions for the `repokid_roles` table and all indexes (specified in `assume_role` subsection of `dynamo_db` in config) and the ability to run `dynamodb:ListTables`

RepokidRole:
- Must exist in every account to be managed by repokid.
- Must have a trust policy allowing `RepokidInstanceProfile`.
- Name must be specified in `connection_iam` in config file.
- Has these permissions:
 ```json
 {
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "iam:DeleteInstanceProfile",
        "iam:DeleteRole",
        "iam:DeleteRolePolicy",
        "iam:GetAccountAuthorizationDetails",
        "iam:GetInstanceProfile",
        "iam:GetRole",
        "iam:GetRolePolicy",
        "iam:ListInstanceProfiles",
        "iam:ListInstanceProfilesForRole",
        "iam:ListRolePolicies",
        "iam:PutRolePolicy",
        "iam:UpdateRoleDescription"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
```

So if you are monitoring `n` accounts, you will always need `n+1` roles. (`n` RepokidRoles and `1` RepokidInstanceProfile).

#### Editing config.json

Running `repokid config config.json` creates a file that you will need to edit.  Find and update these fields:
- `dynamodb`: If using dynamo locally, set the endpoint to `http://localhost:8010`.  If using AWS hosted dynamo, set the `region`, `assume_role`, and `account_number`.
- `aardvark_api_location`: The location to your Aardvark REST API.  Something like `https://aardvark.yourcompany.net/api/1/advisors`
- `connection_iam`: Set `assume_role` to `RepokidRole`, or whatever you have called it.

## Optional Config
Repokid uses filters to decide which roles are candidates to be repoed.  Filters may be configured to suit your
environment as described below.

### Blocklist Filter
Roles may be excluded by adding them to the Blocklist filter.  One common reason to exclude a role is if
the corresponding workload performs occasional actions that may not have been observed but are known to be
required.  There are two ways to exclude a role:

 - Exclude role name for all accounts: add it to a list in the config `filter_config.BlocklistFilter.all`
 - Exclude role name for specific account: add it to a list in the config `filter_config.BlocklistFilter.<ACCOUNT_NUMBER>`

 Blocklists can also be maintained in an S3 blocklist file.  They should be in the following form:
 ```json
 {
   "arns": ["arn1", "arn2"],
   "names": {"role_name_1": ["all", "account_number_1"], "role_name_2": ["account_number_2", "account_number_3"]}
 }
 ```

### Exclusive Filter
If you prefer to repo only certain roles you can use the Exclusive Filter. Maybe you want to consider only roles used in production or by certain teams.
To select roles for repo-ing you may list their names in the configuration files. Shell style glob patterns are also supported.
Role selection can be specified per individual account or globally.
To activate this filter put `"repokid.filters.exclusive:ExclusiveFilter"`in the section `active_filters` of the config file.
To configure it you can start with the autogenerated config file, which has an example config in the `"filter_config"` section:

```
"ExclusiveFilter": {
                   "all": [
                     "<GLOB_PATTERN>"
                     ],
                   "<ACCOUNT_NUMBER>": [
                     "<GLOB_PATTERN>"
                    ]
                   }
```

### Age Filter
By default the age filter excludes roles that are younger than 90 days.  To change this edit the config setting:
`filter_config.AgeFilter.minimum_age`.

### Active Filters

New filters can be created to support internal logic.  At Netflix we have several that are specific to our
use cases.  To make them active make sure they are in the Python path and add them in the config to the list in
the section `active_filters`.

## Extending Repokid

### Hooks

Repokid is extensible via hooks that are called before, during, and after various operations as listed below.

| Hook name | Context |
|-----------|---------|
| `AFTER_REPO` | role, errors |
| `AFTER_REPO_ROLES` | roles, errors |
| `BEFORE_REPO_ROLES` | account_number, roles |
| `AFTER_SCHEDULE_REPO` | roles |
| `DURING_REPOABLE_CALCULATION` | role_id, arn, account_number, role_name, potentially_repoable_permissions, minimum_age |
| `DURING_REPOABLE_CALCULATION_BATCH` | role_batch, potentially_repoable_permissions, minimum_age |

Hooks must adhere to the following interface:

```python
from repokid.hooks import implements_hook
from repokid.types import RepokidHookInput, RepokidHookOutput

@implements_hook("TARGET_HOOK_NAME", 1)
def custom_hook(input_dict: RepokidHookInput) -> RepokidHookOutput:
    """Hook functions are called with a dict containing the keys listed above based on the target hook.
    Any mutations made to the input and returned in the output will be passed on to subsequent hook funtions.
    """
    ...
```

Examples of hook implementations can be found in [`repokid.hooks.loggers`](repokid/hooks/loggers/__init__.py).

### Filters

Custom filters can be written to exclude roles from being repoed. Filters must adhere to the following interface:

```python
from repokid.filters import Filter
from repokid.types import RepokidFilterConfig
from repokid.role import RoleList


class CustomFilterName(Filter):
    def __init__(self, config: RepokidFilterConfig = None) -> None:
        """Filters are initialized with a dict containing the contents of `filter_config.FilterName`
        from the config file. This example would be initialized with `filter_config.CustomFilterName`.
        The configuration can be accessed via `self.config`

        If you don't need any custom initialization logic, you can leave this function out of your
        filter class.
        """
        super().__init__(config=config)
        # custom initialization logic goes here
        ...

    def apply(self, input_list: RoleList) -> RoleList:
        """Determine roles to be excluded and return them as a RoleList"""
        ...
```

A simple filter implementation can be found in [`repokid.filters.age`](repokid/filters/age/__init__.py). A more complex example is in [`repokid.blocklist.age`](repokid/filters/blocklist/__init__.py).

## How to Use

Once Repokid is configured, use it as follows:

### Standard flow
 - Update role cache: `repokid update_role_cache <ACCOUNT_NUMBER>`
 - Display role cache: `repokid display_role_cache <ACCOUNT_NUMBER>`
 - Display information about a specific role: `repokid display_role <ACCOUNT_NUMBER> <ROLE_NAME>`
 - Repo a specific role: `repokid repo_role <ACCOUNT_NUMBER> <ROLE_NAME>`
 - Repo all roles in an account: `repokid repo_all_roles <ACCOUNT_NUMBER> -c`

### Scheduling
Rather than running a repo right now you can schedule one (`schedule_repo` command). The duration between scheduling and eligibility is configurable, but by default roles can be repoed 7 days after scheduling.  You can then run a command `repo_scheduled_roles` to only repo roles which have already been scheduled.

### Targeting a specific permission

Say that you find a given permission especially dangerous in your environment.  Here I'll use `s3:PutObjectACL` as an example. You can use Repokid to find all roles that have this permission (even those hidden in a wildcard), and then remove just that single permission.

Find & Remove:
 - Ensure the role cache is updated before beginning.
 - Find roles with a given permission: `repokid find_roles_with_permissions <permission>... [--output=ROLE_FILE]`
 - Remove permission from roles: `repokid remove_permissions_from_roles --role-file=ROLE_FILE <permission>... [-c]`

Example:
```
$ repokid find_roles_with_permissions "s3:putobjectacl" "sts:assumerole" --output=myroles.json
...
$ repokid remove_permissions_from_roles --role-file=myroles.json "s3:putobjectacl" "sts:assumerole" -c
```

### Rolling back
Repokid stores a copy of each version of inline policies it knows about.  These are added when
a different version of a policy is found during `update_role_cache` and any time a repo action
occurs.  To restore a previous version run:

See all versions of roles: `repokid rollback_role <ACCOUNT_NUMBER> <ROLE_NAME>`
Restore a specific version: `repokid rollback_role <ACCOUNT_NUMBER> <ROLE_NAME> --selection=<NUMBER> -c`

### Stats
Repokid keeps counts of the total permissions for each role.  Stats are added any time an `update_role_cache` or
`repo_role` action occur.  To output all stats to a CSV file run: `repokid repo_stats <OUTPUT_FILENAME>`.  An optional account number can be specified to output stats for a specific account only.

### Library

> New in `v0.14.2`

Repokid can be called as a library using the `repokid.lib` module:

```python
from repokid.lib import display_role, repo_role, update_role_cache

account_number = "123456789012"

display_role(account_number, "superCoolRoleName")
update_role_cache(account_number)
repo_role(account_number, "superCoolRoleName", commit=True)
```

## Dispatcher ##
Repokid Dispatcher is designed to listen for messages on a queue and perform actions.  So far the actions are:
 - List repoable services from a role
 - Set or remove an opt-out
 - List and perform rollbacks for a role

Repokid will respond on a configurable SNS topic with information about any success or failures. The Dispatcher
component exists to help with operationalization of the repo lifecycle across your organization. You may choose
to expose the queue directly to developers, but more likely this should be guarded because rolling back can be
a destructive action if not done carefully.

## Development

### Releasing

Versioning is handled by [setupmeta](https://github.com/zsimic/setupmeta). To create a new release:

```bash
python setup.py version --bump patch --push

# Inspect output and make sure it's what you expect
# If all is well, commit and push the new tag:
python setup.py version --bump patch --push --commit
```
