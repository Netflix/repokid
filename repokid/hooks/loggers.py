from repokid import LOGGER
import repokid.hooks as hooks


@hooks.implements_hook('DURING_REPOABLE_CALCULATION', 1)
def check_and_log_during_repoable_calculation_hooks(input_dict):
    LOGGER.debug("Calling DURING_REPOABLE_CALCULATION hooks")
    if not all(['role_name', 'potentially_repoable_permissions', 'minimum_age']
               in input_dict):
        raise hooks.MissingHookParamaeter


@hooks.implements_hook('AFTER_SCHEDULE_REPO', 1)
def check_and_log_after_schedule_repo_hooks(input_dict):
    LOGGER.debug("Calling AFTER_SCHEDULE_REPO hooks")
    if 'roles' not in input_dict:
        raise hooks.MissingHookParamaeter


@hooks.implements_hook('AFTER_REPO', 1)
def check_and_log_after_repo_hooks():
    LOGGER.debug("Calling AFTER_REPO hooks")
    pass
