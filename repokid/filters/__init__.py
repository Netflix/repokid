import logging

import import_string

LOGGER = logging.getLogger("repokid")


# inspiration from https://github.com/slackhq/python-rtmbot/blob/master/rtmbot/core.py
class FilterPlugins(object):
    """
    FilterPlugins is used to hold a list of instantiated plugins. The internal object filter_plugins contains a list
    of active plugins that can be iterated.
    """

    def __init__(self):
        """Initialize empty list"""
        self.filter_plugins = []

    def load_plugin(self, module, config=None):
        """Import a module by path, instantiate it with plugin specific config and add to the list of active plugins"""
        cls = None
        try:
            cls = import_string(module)
        except ImportError as e:
            LOGGER.warn("Unable to find plugin {}, exception: {}".format(module, e))
        else:
            plugin = None
            try:
                plugin = cls(config=config)
            except KeyError:
                plugin = cls()
            LOGGER.info("Loaded plugin {}".format(module))
            self.filter_plugins.append(plugin)


class Filter(object):
    """Base class for filter plugins to inherit.  Passes config if supplied and requires the apply method be defined"""

    def __init__(self, config=None):
        self.config = config

    def apply(self, input_list):
        raise NotImplementedError
