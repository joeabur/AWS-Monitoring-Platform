import math
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


@dataclass
class _Window:
    started_at: float
    requests: int


class _FixedWindowLimiter:
    def __init__(
        self,
        *,
        limit: int,
        window_seconds: int,
        max_clients: int = 4096,
        clock=time.monotonic,
    ) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self.max_clients = max_clients
        self._clock = clock
        self._windows: OrderedDict[str, _Window] = OrderedDict()
        self._lock = threading.Lock()

    def check(self, key: str) -> int | None:
        now = self._clock()
        with self._lock:
            window = self._windows.get(key)
            if window is None or now - window.started_at >= self.window_seconds:
                self._windows[key] = _Window(started_at=now, requests=1)
                self._windows.move_to_end(key)
                while len(self._windows) > self.max_clients:
                    self._windows.popitem(last=False)
                return None

            self._windows.move_to_end(key)
            if window.requests >= self.limit:
                return max(1, math.ceil(self.window_seconds - (now - window.started_at)))
            window.requests += 1
            return None


class LoginRateLimitMiddleware(BaseHTTPMiddleware):
    """Best-effort per-process login throttling; use a shared ingress limiter in production."""

    def __init__(
        self,
        app,
        *,
        limit: int = 10,
        window_seconds: int = 60,
        max_clients: int = 4096,
    ) -> None:
        super().__init__(app)
        self._limiter = _FixedWindowLimiter(
            limit=limit,
            window_seconds=window_seconds,
            max_clients=max_clients,
        )

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.method != "POST" or request.url.path != "/api/v1/auth/login":
            return await call_next(request)
        client = request.client
        key = client.host if client is not None else "unknown"
        retry_after = self._limiter.check(key)
        if retry_after is not None:
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many login attempts"},
                headers={"Retry-After": str(retry_after)},
            )
        return await call_next(request)
