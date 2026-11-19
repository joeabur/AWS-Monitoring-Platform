from typing import Any

from pydantic import BaseModel, Field


class McpJsonRpcRequest(BaseModel):
    jsonrpc: str = Field(pattern=r"^2\.0$")
    id: str | int
    method: str = Field(min_length=1, max_length=128)
    params: dict[str, Any] = Field(default_factory=dict)
