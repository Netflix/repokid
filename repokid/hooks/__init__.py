from typing import Callable

from repokid.types import RepokidHook
from repokid.types import RepokidHookInput
from repokid.types import RepokidHookOutput
from repokid.types import RepokidHooks


def call_hooks(
    hooks_dict: RepokidHooks, hook_name: str, inputs_dict: RepokidHookInput
) -> RepokidHookOutput:
    """
    Call all hooks of a given name in order.  The output of one function is the input to the next.  Return the final
    output.

    Args:
        hooks_dict: Dict with all functions to run for each hook name
        hook_name: The selected hook name to run
        inputs_dict: All required inputs

    Returns:
        dict: Outputs of the final function in the chain
    """
    if hook_name not in hooks_dict:
        return inputs_dict

    for func in hooks_dict[hook_name]:
        inputs_dict = func(inputs_dict)
        if not inputs_dict:
            raise MissingOutputInHook("Function {} didn't return output".format(func))
    return inputs_dict


def implements_hook(
    hook_name: str, priority: int
) -> Callable[[RepokidHook], RepokidHook]:
    def _implements_hook(func: RepokidHook) -> RepokidHook:
        if not hasattr(func, "_implements_hook"):
            setattr(
                func, "_implements_hook", {"hook_name": hook_name, "priority": priority}
            )
        return func

    return _implements_hook


class MissingHookParameter(Exception):
    pass


class MissingOutputInHook(Exception):
    pass
