#     Copyright 2020 Netflix, Inc.
#
#     Licensed under the Apache License, Version 2.0 (the "License");
#     you may not use this file except in compliance with the License.
#     You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS,
#     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#     See the License for the specific language governing permissions and
#     limitations under the License.
import collections
import inspect
import json
import logging
import logging.config
import os
from typing import DefaultDict
from typing import List
from typing import Tuple

import import_string

from repokid.types import RepokidConfig
from repokid.types import RepokidHook
from repokid.types import RepokidHooks

__version__ = "0.17.10"


def init_config() -> RepokidConfig:
    """
    Try to find config by searching for it in a few paths, load it, and store it in the global CONFIG

    Args:
        account_number (string): The current account number Repokid is being run against. This is needed to provide
                                 the right config to the blocklist filter.

    Returns:
        None
    """
    load_config_paths = [
        os.path.join(os.getcwd(), "config.json"),
        "/etc/repokid/config.json",
        "/apps/repokid/config.json",
    ]
    config: RepokidConfig = {}
    for path in load_config_paths:
        try:
            with open(path, "r") as f:
                print("Loaded config from {}".format(path))
                config = json.load(f)
                return config

        except IOError:
            print("Unable to load config from {}, trying next location".format(path))

    print("Config not found in any path, using defaults")
    return config


def init_logging() -> logging.Logger:
    """
    Initialize global LOGGER object with config defined in the global CONFIG object

    Args:
        None

    Returns:
        None
    """

    if CONFIG:
        logging.config.dictConfig(CONFIG["logging"])

    # these loggers are very noisy
    suppressed_loggers = [
        "botocore.vendored.requests.packages.urllib3.connectionpool",
        "urllib3",
        "botocore.credentials",
    ]

    for logger in suppressed_loggers:
        logging.getLogger(logger).setLevel(logging.ERROR)

    log = logging.getLogger(__name__)
    log.propagate = False
    return log


def get_hooks(hooks_list: List[str]) -> RepokidHooks:
    """
    Output should be a dictionary with keys as the names of hooks and values as a list of functions (in order) to call

    Args:
        hooks_list: A list of paths to load hooks from

    Returns:
        dict: Keys are hooks by name (AFTER_SCHEDULE_REPO) and values are a list of functions to execute
    """
    # hooks is a temporary dictionary of priority/RepokidHook tuples
    hooks: DefaultDict[str, List[Tuple[int, RepokidHook]]] = collections.defaultdict(
        list
    )

    for hook in hooks_list:
        module = import_string(hook)
        # get members retrieves all the functions from a given module
        all_funcs = inspect.getmembers(module, inspect.isfunction)
        # first argument is the function name (which we don't need)
        for (_, func) in all_funcs:
            # we only look at functions that have been decorated with _implements_hook
            if hasattr(func, "_implements_hook"):
                h: Tuple[int, RepokidHook] = (func._implements_hook["priority"], func)
                # append to the dictionary in whatever order we see them, we'll sort later. Dictionary value should be
                # a list of tuples (priority, function)
                hooks[func._implements_hook["hook_name"]].append(h)

    # sort by priority
    for k in hooks.keys():
        hooks[k] = sorted(hooks[k], key=lambda priority: int(priority[0]))
    # get rid of the priority - we don't need it anymore
    # save to a new dict that conforms to the RepokidHooks spec
    final_hooks: RepokidHooks = RepokidHooks()
    for k in hooks.keys():
        final_hooks[k] = [func_tuple[1] for func_tuple in hooks[k]]

    return final_hooks


CONFIG: RepokidConfig = init_config()
LOGGER: logging.Logger = init_logging()
