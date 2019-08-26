def call_hooks(hooks_dict, hook_name, inputs_dict):
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
    for func in hooks_dict[hook_name]:
        inputs_dict = func(inputs_dict)
        if not inputs_dict:
            raise MissingOutputInHook("Function {} didn't return output".format(func))
    return inputs_dict


def implements_hook(hook_name, priority):
    def _implements_hook(func):
        if not hasattr(func, "_implements_hook"):
            func._implements_hook = {"hook_name": hook_name, "priority": priority}
        return func

    return _implements_hook


class MissingHookParamaeter(Exception):
    pass


class MissingOutputInHook(Exception):
    pass
