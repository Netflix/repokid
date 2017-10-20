from repokid import LOGGER
import repokid.hooks as hooks


@hooks.implements_hook('DURING_REPOABLE_CALCULATION', 1)
def log_during_repoable_calculation_hooks(input_dict):
    LOGGER.debug("Calling DURING_REPOABLE_CALCULATION hooks")
    if not all(required in input_dict for required in['account_number', 'role_name', 'potentially_repoable_permissions',
                                                      'minimum_age']):
        raise hooks.MissingHookParamaeter("Did not get all required parameters for DURING_REPOABLE_CALCULATION hook")
    return input_dict


@hooks.implements_hook('AFTER_SCHEDULE_REPO', 1)
def log_after_schedule_repo_hooks(input_dict):
    LOGGER.debug("Calling AFTER_SCHEDULE_REPO hooks")
    if 'roles' not in input_dict:
        raise hooks.MissingHookParamaeter("Required key 'roles' not passed to AFTER_SCHEDULE_REPO")
    return input_dict


@hooks.implements_hook('AFTER_REPO', 1)
def log_after_repo_hooks(input_dict):
    LOGGER.debug("Calling AFTER_REPO hooks")
    if 'role' not in input_dict:
        raise hooks.MissingHookParamaeter("Required key 'role' not passed to AFTER_REPO")
    return input_dict
