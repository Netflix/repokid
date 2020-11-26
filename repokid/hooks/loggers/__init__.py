import logging

import repokid.hooks as hooks
from repokid.role import Role
from repokid.types import RepokidHookInput
from repokid.types import RepokidHookOutput

LOGGER = logging.getLogger("repokid")


@hooks.implements_hook("BEFORE_REPO_ROLES", 1)
def log_before_repo_roles(input_dict: RepokidHookInput) -> RepokidHookOutput:
    LOGGER.debug("Calling DURING_REPOABLE_CALCULATION hooks")
    if not all(required in input_dict for required in ["account_number", "roles"]):
        raise hooks.MissingHookParameter(
            "Did not get all required parameters for BEFORE_REPO_ROLES hook"
        )
    return input_dict


@hooks.implements_hook("DURING_REPOABLE_CALCULATION", 1)
def log_during_repoable_calculation_hooks(
    input_dict: RepokidHookInput,
) -> RepokidHookOutput:
    LOGGER.debug("Calling DURING_REPOABLE_CALCULATION hooks")
    if not all(
        required in input_dict
        for required in [
            "account_number",
            "role_name",
            "potentially_repoable_permissions",
            "minimum_age",
        ]
    ):
        raise hooks.MissingHookParameter(
            "Did not get all required parameters for DURING_REPOABLE_CALCULATION hook"
        )
    return input_dict


@hooks.implements_hook("DURING_REPOABLE_CALCULATION_BATCH", 1)
def log_during_repoable_calculation_batch_hooks(
    input_dict: RepokidHookInput,
) -> RepokidHookOutput:
    LOGGER.debug("Calling DURING_REPOABLE_CALCULATION_BATCH hooks")

    if not all(
        required in input_dict
        for required in [
            "role_batch",
            "potentially_repoable_permissions",
            "minimum_age",
        ]
    ):
        raise hooks.MissingHookParameter(
            "Did not get all required parameters for DURING_REPOABLE_CALCULATION_BATCH hook"
        )
    for role in input_dict["role_batch"]:
        if not isinstance(role, Role):
            raise hooks.MissingHookParameter(
                "Role_batch needs to be a series of Role objects in DURING_REPOABLE_CALCULATION_BATCH hook"
            )
    return input_dict


@hooks.implements_hook("AFTER_SCHEDULE_REPO", 1)
def log_after_schedule_repo_hooks(input_dict: RepokidHookInput) -> RepokidHookOutput:
    LOGGER.debug("Calling AFTER_SCHEDULE_REPO hooks")
    if "roles" not in input_dict:
        raise hooks.MissingHookParameter(
            "Required key 'roles' not passed to AFTER_SCHEDULE_REPO"
        )
    return input_dict


@hooks.implements_hook("AFTER_REPO", 1)
def log_after_repo_hooks(input_dict: RepokidHookInput) -> RepokidHookOutput:
    LOGGER.debug("Calling AFTER_REPO hooks")
    if "role" not in input_dict:
        raise hooks.MissingHookParameter("Required key 'role' not passed to AFTER_REPO")
    return input_dict
