from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.detections import router as detections_router
from app.api.events import router as events_router
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
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)
app.include_router(router)
app.include_router(events_router)
app.include_router(detections_router)
