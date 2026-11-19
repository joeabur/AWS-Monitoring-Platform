import json
from typing import Any

from fastapi import APIRouter, HTTPException, status

from app.api.dependencies import CurrentUser, Database
from app.core.config import get_settings
from app.mcp.server import call_tool, tool_definitions
from app.schemas.mcp import McpJsonRpcRequest

router = APIRouter(prefix="/api/v1/mcp", tags=["mcp"])


def _disabled() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={"code": "McpDisabled"},
    )


@router.get("/capabilities")
def capabilities(_: CurrentUser) -> dict[str, Any]:
    if not get_settings().mcp_enabled:
        raise _disabled()
    return {
        "protocolVersion": "2024-11-05",
        "serverInfo": {"name": "aws-monitoring-platform", "version": "1.0.0"},
        "capabilities": {"tools": {"listChanged": False}},
    }


@router.post("")
def mcp_endpoint(
    payload: McpJsonRpcRequest,
    db: Database,
    _: CurrentUser,
) -> dict[str, Any]:
    if not get_settings().mcp_enabled:
        raise _disabled()

    try:
        if payload.method == "initialize":
            result = {
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": "aws-monitoring-platform", "version": "1.0.0"},
                "capabilities": {"tools": {"listChanged": False}},
            }
        elif payload.method == "tools/list":
            result = {"tools": tool_definitions()}
        elif payload.method == "tools/call":
            name = payload.params.get("name")
            arguments = payload.params.get("arguments", {})
            if not isinstance(name, str) or not isinstance(arguments, dict):
                raise ValueError("Invalid tool call")
            result = {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(call_tool(db, name, arguments), sort_keys=True),
                    }
                ]
            }
        else:
            return {
                "jsonrpc": "2.0",
                "id": payload.id,
                "error": {"code": -32601, "message": "Method not found"},
            }
        return {"jsonrpc": "2.0", "id": payload.id, "result": result}
    except LookupError as exc:
        return {
            "jsonrpc": "2.0",
            "id": payload.id,
            "error": {"code": -32602, "message": str(exc)},
        }
    except ValueError as exc:
        return {
            "jsonrpc": "2.0",
            "id": payload.id,
            "error": {"code": -32602, "message": str(exc)},
        }
