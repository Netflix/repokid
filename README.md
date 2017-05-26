# Repokid #

Repokid uses Access Advisor provided by [Aardvark](https://github.com/Netflix-Skunkworks/aardvark)
to remove permissions granting access to unused services from the inline policies of IAM roles in
an AWS account.

## Getting Started

To use Repokid you will need:
 - A [DynamoDB](https://aws.amazon.com/dynamodb/) table called `repokid_roles` (specify account and endpoint in `dynamo_db` in config file)
 
 - An IAM role with the following permissions (specified in `connection_iam` in config file):
 ```{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Stmt1495554068860",
      "Action": [
        "iam:DeleteInstanceProfile",
        "iam:DeleteRole",
        "iam:DeleteRolePolicy",
        "iam:GetInstanceProfile",
        "iam:GetRole",
        "iam:GetRolePolicy",
        "iam:ListInstanceProfiles",
        "iam:ListInstanceProfilesForRole",
        "iam:ListRolePolicies",
        "iam:ListRoles",
        "iam:PutRolePolicy"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
```

 - An IAM role with DyamoDB permissions for the `repokid_roles` table and all indexes (specified in `assume_role` subsection of `dynamo_db` in config)

## Optional Config
Repokid uses filters to decide which roles are candidates to be repoed.  Filters may be configured to suit your
environment as described below.

### Blacklist Filter
Roles may be excluded by adding them to the Blacklist filter.  One common reason to exclude a role is if
the corresponding workload performs occasional actions that may not have been observed but are known to be
required.  There are two ways to exclude a role:

 - Exclude role name for all accounts: add it to a list in the config `filter_config.BlacklistFilter.all`
 - Exclude role name for specific account: add it to a list in the config `filter_config.BlacklistFilter.<ACCOUNT_NUMBER>`

### Age Filter
By default the age filter excludes roles that are younger than 90 days.  To change this edit the config setting:
`filter_config.AgeFilter.minimum_age`.

### Active Filters
New filters can be created to support internal logic.  At Netflix we have several that are specific to our
use cases.  To make them active make sure they are in the Python path and add them in the config to the list in
the section `active_filters`.

## How to Use
Once Repokid is configured use it as follows:

### Standard flow
 - Update role cache: `repokid update_role_cache <ACCOUNT_NUMBER>`
 - Display role cache: `repokid display_role_cache <ACCOUNT_NUMBER>`
 - Display information about a specific role: `repokid display_role <ACCOUNT_NUMBER> <ROLE_NAME>`
 - Repo a specific role: `repokid repo_role <ACCOUNT_NUMBER> <ROLE_NAME>`
 - Repo all roles in an account: `repokid repo_all_roles <ACCOUNT_NUMBER> -c`

### Rolling back
Repokid stores a copy of each version of inline policies it knows about.  These are added when
a different version of a policy is found during `update_role_cache` and any time a repo action
occurs.  To restore a previous version run:

See all versions of roles: `repokid rollback_role <ACCOUNT_NUMBER> <ROLE_NAME>`
Restore a specific version: `repokid rollback_role <ACCOUNT_NUMBER> <ROLE_NAME> --selection=<NUMBER> -c`

### Stats
Repokid keeps counts of the total permissions for each role.  Stats are added any time an `update_role_cache` or
`repo_role` action occur.  To output all stats to a CSV file run: `repokid repo_stats <OUTPUT_FILENAME>`.  An optional account number can be specified to output stats for a specific account only.

## Developing locally
You can run a DynamoDB development server locally by [downloading it](http://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DynamoDBLocal.html)

To run:
  `java -Djava.library.path=./DynamoDBLocal_lib -jar DynamoDBLocal.jar -sharedDb -inMemory -port 8010`
  
## TODO
[TODO](TODO.md)
