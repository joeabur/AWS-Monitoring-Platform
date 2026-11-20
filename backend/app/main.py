import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.api.accounts import router as accounts_router
from app.api.audit_reports import router as audit_reports_router
from app.api.dashboard import router as dashboard_router
from app.api.detections import router as detections_router
from app.api.events import router as events_router
from app.api.findings import router as findings_router
from app.api.incidents import router as incidents_router
from app.api.mcp import router as mcp_router
from app.api.notifications import router as notifications_router
from app.api.response import router as response_router
from app.api.routes import router
from app.core.config import get_settings
from app.middleware.rate_limit import LoginRateLimitMiddleware
from app.middleware.request_id import RequestIdMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.telemetry import emit_emf_metric


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    if settings.auth_provider == "local":
        settings.require_jwt_secret()
    yield


app = FastAPI(
    title="AWS Cloud Security Monitoring Platform",
    description="Continuous AWS security event monitoring and incident management.",
    version="0.1.0",
    lifespan=lifespan,
)


@app.middleware("http")
async def emit_request_metrics(request: Request, call_next) -> Response:
    started_at = time.perf_counter()
    status_code = 500
    try:
        response = await call_next(request)
        status_code = response.status_code
        return response
    finally:
        emit_emf_metric(
            {
                "_aws": {
                    "Timestamp": int(time.time() * 1000),
                    "CloudWatchMetrics": [
                        {
                            "Namespace": "AWSMonitoringPlatform",
                            "Dimensions": [["Service", "StatusClass"]],
                            "Metrics": [
                                {"Name": "ApiRequests", "Unit": "Count"},
                                {"Name": "ApiLatency", "Unit": "Milliseconds"},
                            ],
                        }
                    ],
                },
                "Service": "api",
                "StatusClass": f"{status_code // 100}xx",
                "ApiRequests": 1,
                "ApiLatency": round((time.perf_counter() - started_at) * 1000, 2),
            }
        )


app.add_middleware(LoginRateLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestIdMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    expose_headers=["X-Request-ID"],
)
app.include_router(router)
app.include_router(accounts_router)
app.include_router(audit_reports_router)
app.include_router(dashboard_router)
app.include_router(events_router)
app.include_router(findings_router)
app.include_router(detections_router)
app.include_router(incidents_router)
app.include_router(notifications_router)
app.include_router(response_router)
app.include_router(mcp_router)
