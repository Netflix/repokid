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
from typing import Any
from typing import Dict
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


class M_A(type):
    pass


class Singleton(M_A):
    _instances: Dict[str, Singleton] = {}

    def __call__(cls, *args: Any, **kwargs: Any) -> Singleton:
        if cls.__name__ not in cls._instances:
            cls._instances[cls.__name__] = super(Singleton, cls).__call__(
                *args, **kwargs
            )
        return cls._instances[cls.__name__]
