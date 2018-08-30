Repokid
=======
[![NetflixOSS Lifecycle](https://img.shields.io/osslifecycle/Netflix/osstracker.svg)]()
[![Build Status](https://travis-ci.org/Netflix/repokid.svg?branch=master)](https://travis-ci.org/Netflix/repokid)
[![Coverage Status](https://coveralls.io/repos/github/Netflix/repokid/badge.svg?branch=master)](https://coveralls.io/github/Netflix/repokid?branch=master)
[![Gitter chat](https://badges.gitter.im/gitterHQ/gitter.png)](https://gitter.im/netflix-repokid)

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
python setup.py develop
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
  `java -Djava.library.path=./DynamoDBLocal_lib -jar DynamoDBLocal.jar -sharedDb -inMemory -port 8010`
  
If you run the development version the table and index will be created for you automatically.
 
 #### IAM Permissions:

Repokid needs an IAM Role in each account that will be queried.  Additionally, Repokid needs to be launched with a role or user which can `sts:AssumeRole` into the different account roles.

RepokidInstanceProfile:
- Only create one.
- Needs the ability to call `sts:AssumeRole` into all of the RepokidRoles.
- DyamoDB permissions for the `repokid_roles` table and all indexes (specified in `assume_role` subsection of `dynamo_db` in config) and the ability to run `dynamodb:ListTables`

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
        "iam:ListRoles",
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

### Blacklist Filter
Roles may be excluded by adding them to the Blacklist filter.  One common reason to exclude a role is if
the corresponding workload performs occasional actions that may not have been observed but are known to be
required.  There are two ways to exclude a role:

 - Exclude role name for all accounts: add it to a list in the config `filter_config.BlacklistFilter.all`
 - Exclude role name for specific account: add it to a list in the config `filter_config.BlacklistFilter.<ACCOUNT_NUMBER>`
 
 Blacklists can also be maintained in an S3 blacklist file.  They should be in the following form:
 ```json
 {
   "arns": ["arn1", "arn2"],
   "names": {"role_name_1": ["all", "account_number_1"], "role_name_2": ["account_number_2", "account_number_3"]}
 }
 ```

### Age Filter
By default the age filter excludes roles that are younger than 90 days.  To change this edit the config setting:
`filter_config.AgeFilter.minimum_age`.

### Active Filters
New filters can be created to support internal logic.  At Netflix we have several that are specific to our
use cases.  To make them active make sure they are in the Python path and add them in the config to the list in
the section `active_filters`.

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

### Rolling back
Repokid stores a copy of each version of inline policies it knows about.  These are added when
a different version of a policy is found during `update_role_cache` and any time a repo action
occurs.  To restore a previous version run:

See all versions of roles: `repokid rollback_role <ACCOUNT_NUMBER> <ROLE_NAME>`
Restore a specific version: `repokid rollback_role <ACCOUNT_NUMBER> <ROLE_NAME> --selection=<NUMBER> -c`

### Stats
Repokid keeps counts of the total permissions for each role.  Stats are added any time an `update_role_cache` or
`repo_role` action occur.  To output all stats to a CSV file run: `repokid repo_stats <OUTPUT_FILENAME>`.  An optional account number can be specified to output stats for a specific account only.

## Dispatcher ##
Repokid Dispatcher is designed to listen for messages on a queue and perform actions.  So far the actions are:
 - List repoable services from a role
 - Set or remove an opt-out
 - List and perform rollbacks for a role
 
Repokid will respond on a configurable SNS topic with information about any success or failures. The Dispatcher
component exists to help with operationalization of the repo lifecycle across your organization. You may choose
to expose the queue directly to developers, but more likely this should be guarded because rolling back can be
a destructive action if not done carefully.
