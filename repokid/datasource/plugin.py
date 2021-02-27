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

import logging
from typing import Dict
from typing import Generic
from typing import ItemsView
from typing import Iterable
from typing import Iterator
from typing import List
from typing import Optional
from typing import ValuesView
from typing import cast

from repokid.plugin import RepokidPlugin
from repokid.types import KT
from repokid.types import VT
from repokid.types import RepokidConfig

logger = logging.getLogger("repokid")


class DatasourcePlugin(RepokidPlugin, Generic[KT, VT]):
    """A dict-like container that can be used to retrieve and store data"""

    _data: Dict[KT, VT]
    _seeded: List[str]

    def __init__(self, config: Optional[RepokidConfig] = None):
        super().__init__(config=config)
        self._data = {}
        self._seeded = []

    def __getitem__(self, name: KT) -> VT:
        return self._data[name]

    def __iter__(self) -> Iterator[VT]:
        return iter(cast(Iterable[VT], self._data))

    def keys(self) -> Iterable[KT]:
        return self._data.keys()

    def items(self) -> ItemsView[KT, VT]:
        return self._data.items()

    def values(self) -> ValuesView[VT]:
        return self._data.values()

    def get(self, identifier: KT) -> VT:
        raise NotImplementedError

    def seed(self, identifier: KT) -> Iterable[KT]:
        raise NotImplementedError

    def reset(self) -> None:
        logger.debug("resetting %s", type(self).__name__)
        self._data = {}
        self._seeded = []
