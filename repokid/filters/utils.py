from typing import Optional

from repokid import CONFIG
from repokid.filters import FilterPlugins
from repokid.types import RepokidConfig


def get_filter_plugins(
    account_number: str, config: Optional[RepokidConfig] = None
) -> FilterPlugins:
    config = config or CONFIG

    plugins = FilterPlugins()
    # Blocklist needs to know the current account
    filter_config = config["filter_config"]
    blocklist_filter_config = filter_config.get(
        "BlocklistFilter", filter_config.get("BlacklistFilter")
    )
    blocklist_filter_config["current_account"] = account_number

    for plugin_path in config.get("active_filters", []):
        plugin_name = plugin_path.split(":")[1]
        if plugin_name == "ExclusiveFilter":
            # ExclusiveFilter plugin active; try loading its config. Also, it requires the current account, so add it.
            exclusive_filter_config = filter_config.get("ExclusiveFilter", {})
            exclusive_filter_config["current_account"] = account_number
        plugins.load_plugin(
            plugin_path, config=config["filter_config"].get(plugin_name, None)
        )

    return plugins
