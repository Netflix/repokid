from typing import Any
from typing import Callable
from typing import DefaultDict
from typing import Dict
from typing import List
from typing import Optional

RepokidConfig = Dict[str, Any]
RepokidFilterConfig = Optional[Dict[str, Any]]
RepokidHook = Callable[[Dict[str, Any]], Dict[str, Any]]
RepokidHooks = DefaultDict[str, List[RepokidHook]]
RepokidHookInput = Dict[str, Any]
RepokidHookOutput = RepokidHookInput
