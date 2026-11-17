from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.accounts import router as accounts_router
from app.api.audit_reports import router as audit_reports_router
from app.api.dashboard import router as dashboard_router
from app.api.detections import router as detections_router
from app.api.events import router as events_router
from app.api.findings import router as findings_router
from app.api.incidents import router as incidents_router
from app.api.notifications import router as notifications_router
from app.api.response import router as response_router
from app.api.routes import router
from app.core.config import get_settings


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    get_settings().require_jwt_secret()
    yield


app = FastAPI(
    title="AWS Cloud Security Monitoring Platform",
    description="Continuous AWS security event monitoring and incident management.",
    version="0.1.0",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT"],
    allow_headers=["Authorization", "Content-Type"],
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
