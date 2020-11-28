from typing import List

from pydantic import Field
from pydantic.main import BaseModel


class Message(BaseModel):
    account: str
    command: str
    role_name: str
    respond_channel: str
    errors: List[str] = Field(default=[])
    respond_user: str = Field(default="")
    requestor: str = Field(default="")
    reason: str = Field(default="")
    selection: str = Field(default="")
