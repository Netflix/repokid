from __future__ import annotations

import logging
from typing import List

import import_string

from repokid.role import RoleList
from repokid.types import RepokidFilterConfig

LOGGER = logging.getLogger("repokid")


# inspiration from https://github.com/slackhq/python-rtmbot/blob/master/rtmbot/core.py
class FilterPlugins:
    """
    FilterPlugins is used to hold a list of instantiated plugins. The internal object filter_plugins contains a list
    of active plugins that can be iterated.
    """

    def __init__(self) -> None:
        """Initialize empty list"""
        self.filter_plugins: List[Filter] = []

    def load_plugin(self, module: str, config: RepokidFilterConfig = None) -> None:
        """Import a module by path, instantiate it with plugin specific config and add to the list of active plugins"""
        cls = None
        try:
            cls = import_string(module)
        except ImportError as e:
            LOGGER.warn("Unable to find plugin {}, exception: {}".format(module, e))
        else:
            try:
                plugin = cls(config=config)
            except KeyError:
                plugin = cls()
            LOGGER.info("Loaded plugin {}".format(module))
            self.filter_plugins.append(plugin)


class Filter:
    """Base class for filter plugins to inherit.  Passes config if supplied and requires the apply method be defined"""

    def __init__(self, config: RepokidFilterConfig = None) -> None:
        self.config = config

    def apply(self, input_list: RoleList) -> RoleList:
        raise NotImplementedError
