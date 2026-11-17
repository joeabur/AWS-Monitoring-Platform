from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from app.middleware.rate_limit import LoginRateLimitMiddleware, _FixedWindowLimiter


def test_fixed_window_limiter_expires_entries_and_bounds_client_state() -> None:
    now = [0.0]
    limiter = _FixedWindowLimiter(
        limit=2,
        window_seconds=10,
        max_clients=2,
        clock=lambda: now[0],
    )

    assert limiter.check("client-a") is None
    assert limiter.check("client-a") is None
    assert limiter.check("client-a") == 10
    assert limiter.check("client-b") is None
    assert limiter.check("client-c") is None
    assert len(limiter._windows) == 2
    now[0] = 10.0
    assert limiter.check("client-c") is None


def test_login_rate_limit_returns_retry_after_without_limiting_other_routes() -> None:
    async def endpoint(_request):
        return JSONResponse({"ok": True})

    app = Starlette(routes=[Route("/api/v1/auth/login", endpoint, methods=["POST"])])
    limited_app = LoginRateLimitMiddleware(app, limit=1, window_seconds=60)

    with TestClient(limited_app) as client:
        first = client.post("/api/v1/auth/login")
        second = client.post("/api/v1/auth/login")

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.headers["retry-after"].isdigit()
    assert second.json() == {"detail": "Too many login attempts"}
