import re
from uuid import uuid4

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Propagate a bounded correlation identifier for API requests and responses."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        supplied_id = request.headers.get("X-Request-ID", "")
        request_id = supplied_id if _REQUEST_ID_PATTERN.fullmatch(supplied_id) else str(uuid4())
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response
