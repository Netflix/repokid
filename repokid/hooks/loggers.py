from repokid import LOGGER
import repokid.hooks as hooks
from repokid.role import Role


@hooks.implements_hook('DURING_REPOABLE_CALCULATION', 1)
def check_and_log_during_repoable_calculation_hooks(input_dict):
    LOGGER.debug("Calling DURING_REPOABLE_CALCULATION hooks")
    if not all(['role_name', 'potentially_repoable_permissions', 'minimum_age']
               in input_dict):
        raise hooks.MissingHookParamaeter


@hooks.implements_hook('DURING_REPOABLE_CALCULATION_BATCH', 1)
def log_during_repoable_calculation_batch_hooks(input_dict):
    LOGGER.debug("Calling DURING_REPOABLE_CALCULATION_BATCH hooks")

    if not all(required in input_dict for required in['role_batch', 'potentially_repoable_permissions', 'minimum_age']):
        raise hooks.MissingHookParamaeter(
            "Did not get all required parameters for DURING_REPOABLE_CALCULATION_BATCH hook")
    for role in input_dict['role_batch']:
        if not isinstance(role, Role):
            raise hooks.MissingHookParamaeter(
                "Role_batch needs to be a series of Role objects in DURING_REPOABLE_CALCULATION_BATCH hook")
    return input_dict


@hooks.implements_hook('AFTER_SCHEDULE_REPO', 1)
def check_and_log_after_schedule_repo_hooks(input_dict):
    LOGGER.debug("Calling AFTER_SCHEDULE_REPO hooks")
    if 'roles' not in input_dict:
        raise hooks.MissingHookParamaeter


@hooks.implements_hook('AFTER_REPO', 1)
def check_and_log_after_repo_hooks():
    LOGGER.debug("Calling AFTER_REPO hooks")
    pass
