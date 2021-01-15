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

from typing import Dict
from typing import Generic
from typing import ItemsView
from typing import Iterable
from typing import Iterator
from typing import KeysView
from typing import Optional
from typing import TypeVar
from typing import ValuesView
from typing import cast

from repokid.plugin import RepokidPlugin
from repokid.types import RepokidConfig

T = TypeVar("T")


class DatasourcePlugin(RepokidPlugin, Generic[T]):
    """A dict-like container that can be used to retrieve and store data"""

    _data: Dict[str, T]

    def __init__(self, config: Optional[RepokidConfig] = None):
        super().__init__(config=config)
        self._data = {}

    def __getitem__(self, name: str) -> T:
        return self._data[name]

    def __iter__(self) -> Iterator[T]:
        return iter(cast(Iterable[T], self._data))

    def keys(self) -> KeysView[str]:
        return self._data.keys()

    def items(self) -> ItemsView[str, T]:
        return self._data.items()

    def values(self) -> ValuesView[T]:
        return self._data.values()

    def get(self, identifier: str) -> T:
        raise NotImplementedError

    def seed(self, identifier: str) -> None:
        raise NotImplementedError

    def reset(self) -> None:
        self._data = {}
