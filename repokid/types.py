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
from typing import Any
from typing import Callable
from typing import DefaultDict
from typing import Dict
from typing import List
from typing import Optional
from typing import TypeVar

RepokidConfig = Dict[str, Any]
RepokidFilterConfig = Optional[Dict[str, Any]]
RepokidHook = Callable[[Dict[str, Any]], Dict[str, Any]]
RepokidHooks = DefaultDict[str, List[RepokidHook]]
RepokidHookInput = Dict[str, Any]
RepokidHookOutput = RepokidHookInput
AccessAdvisorEntry = List[Dict[str, Any]]
AardvarkResponse = Dict[str, AccessAdvisorEntry]
IAMEntry = Dict[str, Any]

# Reusable typevars for generics
KT = TypeVar("KT")
VT = TypeVar("VT")
