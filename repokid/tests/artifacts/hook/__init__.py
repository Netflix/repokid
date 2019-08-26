import repokid.hooks as hooks


@hooks.implements_hook("TEST_HOOK", 2)
def function_2():
    pass


@hooks.implements_hook("TEST_HOOK", 1)
def function_1():
    pass
