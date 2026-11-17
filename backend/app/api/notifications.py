from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select

from app.api.dependencies import CurrentUser, Database, require_roles
from app.core.config import get_settings
from app.models import NotificationDelivery, User
from app.notifications.service import configured_channels, dispatch_due_notifications
from app.schemas.auth import UserRole
from app.schemas.notifications import (
    NotificationChannelStatus,
    NotificationConfigurationRead,
    NotificationDeliveryPage,
    NotificationDeliveryRead,
    NotificationDispatchResult,
)

router = APIRouter(prefix="/api/v1/notifications", tags=["notifications"])


@router.get("/config", response_model=NotificationConfigurationRead)
def notification_configuration(_: CurrentUser) -> NotificationConfigurationRead:
    settings = get_settings()
    enabled = set(configured_channels(settings))
    return NotificationConfigurationRead(
        minimum_severity=settings.notification_min_severity,
        channels=[
            NotificationChannelStatus(channel=channel, enabled=channel in enabled)
            for channel in ("email", "slack", "teams")
        ],
    )


@router.get("", response_model=NotificationDeliveryPage)
def list_notifications(
    db: Database,
    _: CurrentUser,
    delivery_status: Annotated[
        str | None, Query(alias="status", pattern="^(pending|retrying|delivered|failed)$")
    ] = None,
    channel: Annotated[str | None, Query(pattern="^(email|slack|teams)$")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> NotificationDeliveryPage:
    filters = []
    if delivery_status is not None:
        filters.append(NotificationDelivery.status == delivery_status)
    if channel is not None:
        filters.append(NotificationDelivery.channel == channel)
    total = db.scalar(select(func.count()).select_from(NotificationDelivery).where(*filters)) or 0
    deliveries = db.scalars(
        select(NotificationDelivery)
        .where(*filters)
        .order_by(NotificationDelivery.created_at.desc(), NotificationDelivery.id)
        .limit(limit)
        .offset(offset)
    ).all()
    return NotificationDeliveryPage(items=deliveries, total=total, limit=limit, offset=offset)


@router.post("/process", response_model=NotificationDispatchResult)
def process_notifications(
    db: Database,
    _: Annotated[User, Depends(require_roles(UserRole.ADMINISTRATOR))],
    limit: Annotated[int, Query(ge=1, le=20)] = 10,
) -> NotificationDispatchResult:
    result = dispatch_due_notifications(db, get_settings(), limit=limit)
    return NotificationDispatchResult(**result)


@router.post("/{delivery_id}/retry", response_model=NotificationDeliveryRead)
def retry_notification(
    delivery_id: UUID,
    db: Database,
    _: Annotated[User, Depends(require_roles(UserRole.ADMINISTRATOR))],
) -> NotificationDeliveryRead:
    delivery = db.get(NotificationDelivery, delivery_id)
    if delivery is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Notification delivery not found",
        )
    if delivery.status != "failed":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Only failed notification deliveries can be retried",
        )
    delivery.status = "pending"
    delivery.attempt_count = 0
    delivery.next_attempt_at = datetime.now(UTC)
    delivery.last_error_code = None
    db.commit()
    db.refresh(delivery)
    return NotificationDeliveryRead.model_validate(delivery)
