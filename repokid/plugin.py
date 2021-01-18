#  Copyright 2021 Netflix, Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
from __future__ import annotations

import logging
from typing import Optional

from repokid import CONFIG
from repokid.types import RepokidConfig

logger = logging.getLogger("repokid")


class RepokidPlugin:
    def __init__(self, config: Optional[RepokidConfig] = None):
        if config:
            self.config = config
        else:
            self.config = CONFIG


class Singleton:
    _instance: Optional[Singleton] = None

    def __new__(cls) -> Singleton:
        if not cls._instance:
            # TODO: drop this log line to debug
            logger.info("creating new instance of %s", cls.__name__)
            cls._instance = super(Singleton, cls).__new__(cls)

        # We know that this will always be a Singleton, but mypy doesn't. Rude.
        if isinstance(cls._instance, Singleton):
            return cls._instance
        else:
            raise Exception("something bad happened")
