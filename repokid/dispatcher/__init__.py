import datetime
import time
from collections import namedtuple
from typing import Callable

from repokid import CONFIG
from repokid import get_hooks
from repokid.commands.repo import _rollback_role
from repokid.dispatcher.types import Message
from repokid.exceptions import RoleStoreError
from repokid.role import Role
from repokid.utils.dynamo import find_role_in_cache
from repokid.utils.permissions import get_permissions_in_policy
from repokid.utils.permissions import get_services_and_permissions_from_repoable

ResponderReturn = namedtuple("ResponderReturn", "successful, return_message")

if CONFIG:
    hooks_list = CONFIG.get("hooks", ["repokid.hooks.loggers"])
else:
    hooks_list = ["repokid.hooks.loggers"]

hooks = get_hooks(hooks_list)
DispatcherCommand = Callable[[Message], ResponderReturn]


def implements_command(
    command: str,
) -> Callable[[DispatcherCommand], DispatcherCommand]:
    def _implements_command(func: DispatcherCommand) -> DispatcherCommand:
        if not hasattr(func, "_implements_command"):
            setattr(func, "_implements_command", command)
        return func

    return _implements_command


@implements_command("list_repoable_services")
def list_repoable_services(message: Message) -> ResponderReturn:
    role_id = find_role_in_cache(message.role_name, message.account)

    if not role_id:
        return ResponderReturn(
            successful=False,
            return_message="Unable to find role {} in account {}".format(
                message.role_name, message.account
            ),
        )
    else:
        role = Role(role_id=role_id)
        role.fetch(fields=["RepoableServices"])

        (
            repoable_permissions,
            repoable_services,
        ) = get_services_and_permissions_from_repoable(role.repoable_services)

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
def list_role_rollbacks(message: Message) -> ResponderReturn:
    role_id = find_role_in_cache(message.role_name, message.account)

    if not role_id:
        return ResponderReturn(
            successful=False,
            return_message="Unable to find role {} in account {}".format(
                message.role_name, message.account
            ),
        )

    role = Role(role_id=role_id)
    role.fetch(fields=["Policies"])
    return_val = "Restorable versions for role {} in account {}\n".format(
        message.role_name, message.account
    )
    for index, policy_version in enumerate(role.policies):
        total_permissions, _ = get_permissions_in_policy(policy_version["Policy"])
        return_val += "({:>3}):  {:<5}     {:<15}  {}\n".format(
            index,
            len(total_permissions),
            policy_version["Discovered"],
            policy_version["Source"],
        )
    return ResponderReturn(successful=True, return_message=return_val)


@implements_command("opt_out")
def opt_out(message: Message) -> ResponderReturn:
    if CONFIG:
        opt_out_period = CONFIG.get("opt_out_period_days", 90)
    else:
        opt_out_period = 90

    if not message.reason or not message.requestor:
        return ResponderReturn(
            successful=False, return_message="Reason and requestor must be specified"
        )

    role_id = find_role_in_cache(message.role_name, message.account)

    if not role_id:
        return ResponderReturn(
            successful=False,
            return_message="Unable to find role {} in account {}".format(
                message.role_name, message.account
            ),
        )

    role = Role(role_id=role_id)
    role.fetch(fields=["OptOut"])
    if role.opt_out:
        timestr = time.strftime("%m/%d/%y", time.localtime(role.opt_out["expire"]))
        return ResponderReturn(
            successful=False,
            return_message=(
                "Role {} in account {} is already opted out by {} for reason {} "
                "until {}".format(
                    message.role_name,
                    message.account,
                    role.opt_out["owner"],
                    role.opt_out["reason"],
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
        role.opt_out = new_opt_out
        try:
            role.store(fields=["opt_out"])
        except RoleStoreError:
            return ResponderReturn(
                successful=False,
                return_message=f"Failed to opt out role {message.role_name} in account {message.account}",
            )
        return ResponderReturn(
            successful=True,
            return_message="Role {} in account {} opted-out until {}".format(
                message.role_name, message.account, expire_dt.strftime("%m/%d/%y")
            ),
        )


@implements_command("remove_opt_out")
def remove_opt_out(message: Message) -> ResponderReturn:
    role_id = find_role_in_cache(message.role_name, message.account)

    if not role_id:
        return ResponderReturn(
            successful=False,
            return_message="Unable to find role {} in account {}".format(
                message.role_name, message.account
            ),
        )

    role = Role(role_id=role_id)
    role.fetch(fields=["OptOut"])

    if not role.opt_out:
        return ResponderReturn(
            successful=False,
            return_message="Role {} in account {} wasn't opted out".format(
                message.role_name, message.account
            ),
        )
    else:
        role.opt_out = {}
        try:
            role.store(fields=["opt_out"])
        except RoleStoreError:
            return ResponderReturn(
                successful=False,
                return_message=f"Failed to cancel opt out for role {message.role_name} in account {message.account}",
            )
        return ResponderReturn(
            successful=True,
            return_message="Cancelled opt-out for role {} in account {}".format(
                message.role_name, message.account
            ),
        )


@implements_command("rollback_role")
def rollback_role(message: Message) -> ResponderReturn:
    if not message.selection:
        return ResponderReturn(
            successful=False, return_message="Rollback must contain a selection number"
        )

    errors = _rollback_role(
        message.account,
        message.role_name,
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
