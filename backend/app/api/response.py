from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select

from app.api.dependencies import CurrentUser, Database, require_roles
from app.core.config import get_settings
from app.models import ResponseAction, ResponseActionAuditEntry, User
from app.response.workflow import (
    ResponseWorkflowError,
    decide_response_action,
    execute_response_action,
    request_access_key_disable,
)
from app.schemas.auth import UserRole
from app.schemas.response import (
    ResponseActionAuditRead,
    ResponseActionCreate,
    ResponseActionDecision,
    ResponseActionDetail,
    ResponseActionPage,
    ResponseActionRead,
    ResponsePlaybookRead,
)

router = APIRouter(prefix="/api/v1/response", tags=["response"])
_WRITE_ROLES = (UserRole.ADMINISTRATOR, UserRole.SECURITY_ANALYST)


def _workflow_http_error(exc: ResponseWorkflowError) -> HTTPException:
    return HTTPException(status_code=exc.status_code, detail={"code": exc.code})


def _get_action(db: Database, action_id: UUID) -> ResponseAction:
    action = db.get(ResponseAction, action_id)
    if action is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Response action not found"
        )
    return action


@router.get("/playbooks", response_model=list[ResponsePlaybookRead])
def list_playbooks(_: CurrentUser) -> list[ResponsePlaybookRead]:
    settings = get_settings()
    accounts = settings.monitored_aws_accounts
    live_enabled = (
        settings.response_actions_enabled
        and not settings.response_dry_run
        and any(
            account.response_role_arn and account.response_allowed_iam_users for account in accounts
        )
    )
    return [
        ResponsePlaybookRead(
            action_type="disable_access_key",
            title="Disable an IAM access key",
            description=(
                "Set a key to Inactive only when its ID appears in the linked incident evidence. "
                "The target IAM username is derived from that evidence."
            ),
            approval_required=True,
            live_enabled=live_enabled,
            dry_run=settings.response_dry_run,
        )
    ]


@router.get("/actions", response_model=ResponseActionPage)
def list_actions(
    db: Database,
    _: CurrentUser,
    incident_id: UUID | None = None,
    action_status: Annotated[
        str | None,
        Query(
            alias="status",
            pattern="^(pending_approval|approved|rejected|dry_run|executed|failed)$",
        ),
    ] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ResponseActionPage:
    filters = []
    if incident_id is not None:
        filters.append(ResponseAction.incident_id == incident_id)
    if action_status is not None:
        filters.append(ResponseAction.status == action_status)
    total = db.scalar(select(func.count()).select_from(ResponseAction).where(*filters)) or 0
    actions = db.scalars(
        select(ResponseAction)
        .where(*filters)
        .order_by(ResponseAction.created_at.desc(), ResponseAction.id)
        .limit(limit)
        .offset(offset)
    ).all()
    return ResponseActionPage(
        items=[ResponseActionRead.model_validate(action) for action in actions],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/actions",
    response_model=ResponseActionRead,
    status_code=status.HTTP_201_CREATED,
)
def create_action(
    payload: ResponseActionCreate,
    db: Database,
    actor: Annotated[User, Depends(require_roles(*_WRITE_ROLES))],
) -> ResponseActionRead:
    try:
        action = request_access_key_disable(
            db,
            payload.incident_id,
            payload.access_key_id,
            payload.reason,
            actor,
        )
    except ResponseWorkflowError as exc:
        raise _workflow_http_error(exc) from exc
    return ResponseActionRead.model_validate(action)


@router.get("/actions/{action_id}", response_model=ResponseActionDetail)
def get_action(action_id: UUID, db: Database, _: CurrentUser) -> ResponseActionDetail:
    action = _get_action(db, action_id)
    audit_trail = db.scalars(
        select(ResponseActionAuditEntry)
        .where(ResponseActionAuditEntry.response_action_id == action.id)
        .order_by(ResponseActionAuditEntry.created_at, ResponseActionAuditEntry.id)
    ).all()
    return ResponseActionDetail(
        response_action=ResponseActionRead.model_validate(action),
        audit_trail=[ResponseActionAuditRead.model_validate(entry) for entry in audit_trail],
    )


@router.post("/actions/{action_id}/approve", response_model=ResponseActionRead)
def approve_action(
    action_id: UUID,
    payload: ResponseActionDecision,
    db: Database,
    actor: Annotated[User, Depends(require_roles(*_WRITE_ROLES))],
) -> ResponseActionRead:
    action = _get_action(db, action_id)
    try:
        decided = decide_response_action(
            db,
            action,
            actor,
            approve=True,
            reason=payload.reason,
        )
    except ResponseWorkflowError as exc:
        raise _workflow_http_error(exc) from exc
    return ResponseActionRead.model_validate(decided)


@router.post("/actions/{action_id}/reject", response_model=ResponseActionRead)
def reject_action(
    action_id: UUID,
    payload: ResponseActionDecision,
    db: Database,
    actor: Annotated[User, Depends(require_roles(*_WRITE_ROLES))],
) -> ResponseActionRead:
    action = _get_action(db, action_id)
    try:
        decided = decide_response_action(
            db,
            action,
            actor,
            approve=False,
            reason=payload.reason,
        )
    except ResponseWorkflowError as exc:
        raise _workflow_http_error(exc) from exc
    return ResponseActionRead.model_validate(decided)


@router.post("/actions/{action_id}/execute", response_model=ResponseActionRead)
def run_action(
    action_id: UUID,
    db: Database,
    actor: Annotated[User, Depends(require_roles(UserRole.ADMINISTRATOR))],
) -> ResponseActionRead:
    action = _get_action(db, action_id)
    settings = get_settings()
    try:
        result = execute_response_action(
            db,
            action,
            actor,
            settings,
            settings.monitored_aws_accounts,
        )
    except ResponseWorkflowError as exc:
        raise _workflow_http_error(exc) from exc
    return ResponseActionRead.model_validate(result)
