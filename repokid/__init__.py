#     Copyright 2017 Netflix, Inc.
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
import json
import logging.config
import os

__version__ = '0.7.8.3'


def init_config():
    """
    Try to find config by searching for it in a few paths, load it, and store it in the global CONFIG

    Args:
        account_number (string): The current account number Repokid is being run against. This is needed to provide
                                 the right config to the blacklist filter.

    Returns:
        None
    """
    load_config_paths = [os.path.join(os.getcwd(), 'config.json'),
                         '/etc/repokid/config.json',
                         '/apps/repokid/config.json']
    for path in load_config_paths:
        try:
            with open(path, 'r') as f:
                print("Loaded config from {}".format(path))
                return json.load(f)

        except IOError:
            print("Unable to load config from {}, trying next location".format(path))

    print("Config not found in any path, using defaults")


def init_logging():
    """
    Initialize global LOGGER object with config defined in the global CONFIG object

    Args:
        None

    Returns:
        None
    """
    if CONFIG:
        logging.config.dictConfig(CONFIG['logging'])

    # these loggers are very noisy
    suppressed_loggers = [
        'botocore.vendored.requests.packages.urllib3.connectionpool',
        'urllib3'
    ]

    for logger in suppressed_loggers:
        logging.getLogger(logger).setLevel(logging.ERROR)

    return logging.getLogger(__name__)


CONFIG = init_config()
LOGGER = init_logging()
