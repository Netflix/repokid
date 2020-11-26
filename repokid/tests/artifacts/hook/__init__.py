import repokid.hooks as hooks
from repokid.types import RepokidHookInput
from repokid.types import RepokidHookOutput


@hooks.implements_hook("TEST_HOOK", 2)
def function_2(input_dict: RepokidHookInput) -> RepokidHookOutput:
    return input_dict


@hooks.implements_hook("TEST_HOOK", 1)
def function_1(input_dict: RepokidHookInput) -> RepokidHookOutput:
    return input_dict
