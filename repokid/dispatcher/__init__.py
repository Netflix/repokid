import datetime
import time
from collections import namedtuple
from typing import Callable

from mypy_boto3_dynamodb.service_resource import Table

import repokid.commands.repo
import repokid.utils.dynamo as dynamo
import repokid.utils.roledata as roledata
from repokid import CONFIG
from repokid import get_hooks
from repokid.dispatcher.types import Message

ResponderReturn = namedtuple("ResponderReturn", "successful, return_message")

if CONFIG:
    hooks_list = CONFIG.get("hooks", ["repokid.hooks.loggers"])
else:
    hooks_list = ["repokid.hooks.loggers"]

hooks = get_hooks(hooks_list)
DispatcherCommand = Callable[[Table, Message], ResponderReturn]


def implements_command(
    command: str,
) -> Callable[[DispatcherCommand], DispatcherCommand]:
    def _implements_command(func: DispatcherCommand) -> DispatcherCommand:
        if not hasattr(func, "_implements_command"):
            setattr(func, "_implements_command", command)
        return func

    return _implements_command


@implements_command("list_repoable_services")
def list_repoable_services(dynamo_table: Table, message: Message) -> ResponderReturn:
    role_id = dynamo.find_role_in_cache(
        dynamo_table, message.account, message.role_name
    )

    if not role_id:
        return ResponderReturn(
            successful=False,
            return_message="Unable to find role {} in account {}".format(
                message.role_name, message.account
            ),
        )
    else:
        role_data = dynamo.get_role_data(
            dynamo_table, role_id, fields=["RepoableServices"]
        )

        (
            repoable_permissions,
            repoable_services,
        ) = roledata._convert_repoed_service_to_sorted_perms_and_services(
            set(role_data.repoable_services)
        )

        repoable_services = role_data.repoable_services
        return ResponderReturn(
            successful=True,
            return_message=(
                "Role {} in account {} has:\n    Repoable Services: \n{}\n\n    Repoable Permissions: \n{}".format(
                    message.role_name,
                    message.account,
                    "\n".join([service for service in repoable_services]),
                    "\n".join([perm for perm in repoable_permissions]),
                )
            ),
        )


@implements_command("list_role_rollbacks")
def list_role_rollbacks(dynamo_table: Table, message: Message) -> ResponderReturn:
    role_id = dynamo.find_role_in_cache(
        dynamo_table, message.account, message.role_name
    )

    if not role_id:
        return ResponderReturn(
            successful=False,
            return_message="Unable to find role {} in account {}".format(
                message.role_name, message.account
            ),
        )
    else:
        role_data = dynamo.get_role_data(dynamo_table, role_id, fields=["Policies"])
        return_val = "Restorable versions for role {} in account {}\n".format(
            message.role_name, message.account
        )
        for index, policy_version in enumerate(role_data.policies):
            total_permissions, _ = roledata.get_permissions_in_policy(
                policy_version["Policy"]
            )
            return_val += "({:>3}):  {:<5}     {:<15}  {}\n".format(
                index,
                len(total_permissions),
                policy_version["Discovered"],
                policy_version["Source"],
            )
        return ResponderReturn(successful=True, return_message=return_val)


@implements_command("opt_out")
def opt_out(dynamo_table: Table, message: Message) -> ResponderReturn:
    if CONFIG:
        opt_out_period = CONFIG.get("opt_out_period_days", 90)
    else:
        opt_out_period = 90

    if not message.reason or not message.requestor:
        return ResponderReturn(
            successful=False, return_message="Reason and requestor must be specified"
        )

    role_id = dynamo.find_role_in_cache(
        dynamo_table, message.account, message.role_name
    )

    if not role_id:
        return ResponderReturn(
            successful=False,
            return_message="Unable to find role {} in account {}".format(
                message.role_name, message.account
            ),
        )

    role_data = dynamo.get_role_data(dynamo_table, role_id, fields=["OptOut"])
    if role_data.opt_out:
        timestr = time.strftime("%m/%d/%y", time.localtime(role_data.opt_out["expire"]))
        return ResponderReturn(
            successful=False,
            return_message=(
                "Role {} in account {} is already opted out by {} for reason {} "
                "until {}".format(
                    message.role_name,
                    message.account,
                    role_data.opt_out["owner"],
                    role_data.opt_out["reason"],
                    timestr,
                )
            ),
        )
    else:
        current_dt = datetime.datetime.fromtimestamp(time.time())
        expire_dt = current_dt + datetime.timedelta(opt_out_period)
        expire_epoch = int((expire_dt - datetime.datetime(1970, 1, 1)).total_seconds())
        new_opt_out = {
            "owner": message.requestor,
            "reason": message.reason,
            "expire": expire_epoch,
        }
        dynamo.set_role_data(dynamo_table, role_id, {"OptOut": new_opt_out})
        return ResponderReturn(
            successful=True,
            return_message="Role {} in account {} opted-out until {}".format(
                message.role_name, message.account, expire_dt.strftime("%m/%d/%y")
            ),
        )


@implements_command("remove_opt_out")
def remove_opt_out(dynamo_table: Table, message: Message) -> ResponderReturn:
    role_id = dynamo.find_role_in_cache(
        dynamo_table, message.account, message.role_name
    )

    if not role_id:
        return ResponderReturn(
            successful=False,
            return_message="Unable to find role {} in account {}".format(
                message.role_name, message.account
            ),
        )

    role_data = dynamo.get_role_data(dynamo_table, role_id, fields=["OptOut"])

    if not role_data.opt_out:
        return ResponderReturn(
            successful=False,
            return_message="Role {} in account {} wasn't opted out".format(
                message.role_name, message.account
            ),
        )
    else:
        dynamo.set_role_data(dynamo_table, role_id, {"OptOut": {}})
        return ResponderReturn(
            successful=True,
            return_message="Cancelled opt-out for role {} in account {}".format(
                message.role_name, message.account
            ),
        )


@implements_command("rollback_role")
def rollback_role(dynamo_table: Table, message: Message) -> ResponderReturn:
    if not message.selection:
        return ResponderReturn(
            successful=False, return_message="Rollback must contain a selection number"
        )

    errors = repokid.commands.repo._rollback_role(
        message.account,
        message.role_name,
        dynamo_table,
        CONFIG,
        hooks,
        selection=int(message.selection),
        commit=True,
    )
    if errors:
        return ResponderReturn(
            successful=False, return_message="Errors during rollback: {}".format(errors)
        )
    else:
        return ResponderReturn(
            successful=True,
            return_message="Successfully rolled back role {} in account {}".format(
                message.role_name, message.account
            ),
        )
