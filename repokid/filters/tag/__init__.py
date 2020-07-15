from repokid import LOGGER
from repokid.filters import Filter


class TagFilter(Filter):
    def apply(self, input_list):
        try:
            tag_key = self.config["tag_key"]
        except KeyError:
            LOGGER.warn("Tag key not set in config, using default repokid_norepo")
            tag_key = "repokid_norepo"

        try:
            tag_value = self.config["tag_value"]
        except KeyError:
            LOGGER.debug("Tag value not set in config, filtering on presence of tag")
            tag_value = ""

        for role in input_list:
            if role.tags:
                LOGGER.debug("role tags %s", role.tags)
