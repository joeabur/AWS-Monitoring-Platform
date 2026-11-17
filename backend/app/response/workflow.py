import re
from datetime import UTC, datetime
from typing import NoReturn
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import MonitoredAwsAccount, Settings
from app.models import (
    CloudTrailEvent,
    DetectionAlert,
    Incident,
    IncidentAlert,
    ResponseAction,
    ResponseActionAuditEntry,
    User,
)
from app.response.service import ResponseActionExecutionError, disable_access_key

_ACCESS_KEY_ID = re.compile(r"^(AKIA|ASIA)[A-Z0-9]{16}$")
_IAM_USER_NAME = re.compile(r"^[A-Za-z0-9+=,.@_-]{1,128}$")
_WRITE_ROLES = {"administrator", "security_analyst"}


class ResponseWorkflowError(RuntimeError):
    def __init__(self, status_code: int, code: str) -> None:
        self.status_code = status_code
        self.code = code
        super().__init__(code)


def _nested_mapping(value: object, key: str) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    child = value.get(key)
    return child if isinstance(child, dict) else {}


def _related_events(db: Session, incident_id: UUID) -> list[CloudTrailEvent]:
    alerts = db.scalars(
        select(DetectionAlert)
        .join(IncidentAlert, IncidentAlert.alert_id == DetectionAlert.id)
        .where(IncidentAlert.incident_id == incident_id)
    ).all()
    event_ids = {UUID(ref) for alert in alerts for ref in alert.event_refs}
    if not event_ids:
        return []
    return db.scalars(select(CloudTrailEvent).where(CloudTrailEvent.id.in_(event_ids))).all()


def _user_for_access_key(
    events: list[CloudTrailEvent],
    account_id: str,
    access_key_id: str,
) -> tuple[str, str | None] | None:
    for event in events:
        if event.account_id != account_id:
            continue
        details = event.event_details
        identity = _nested_mapping(details, "userIdentity")
        parameters = _nested_mapping(details, "requestParameters")
        response = _nested_mapping(details, "responseElements")
        created_key = _nested_mapping(response, "accessKey")
        identity_key_id = identity.get("accessKeyId")
        created_key_id = created_key.get("accessKeyId")

        user_name: str | None = None
        principal_arn = identity.get("arn")
        if identity_key_id == access_key_id and isinstance(principal_arn, str):
            arn_parts = principal_arn.split(":", 5)
            resource = arn_parts[5] if len(arn_parts) == 6 else ""
            if len(arn_parts) == 6 and arn_parts[4] == account_id and resource.startswith("user/"):
                user_name_value = identity.get("userName")
                user_name = (
                    user_name_value
                    if isinstance(user_name_value, str)
                    else resource.removeprefix("user/").rsplit("/", 1)[-1]
                )
                if _IAM_USER_NAME.fullmatch(user_name):
                    return user_name, principal_arn

        if created_key_id == access_key_id:
            user_name_value = parameters.get("userName")
            if isinstance(user_name_value, str) and _IAM_USER_NAME.fullmatch(user_name_value):
                return user_name_value, None
    return None


def _audit(
    db: Session,
    action: ResponseAction,
    actor: User,
    event: str,
    details: dict[str, str],
) -> None:
    db.add(
        ResponseActionAuditEntry(
            id=uuid4(),
            response_action_id=action.id,
            actor_id=actor.id,
            action=event,
            details=details,
            created_at=datetime.now(UTC),
        )
    )


def request_access_key_disable(
    db: Session,
    incident_id: UUID,
    access_key_id: str,
    reason: str,
    actor: User,
) -> ResponseAction:
    if not _ACCESS_KEY_ID.fullmatch(access_key_id):
        raise ResponseWorkflowError(422, "InvalidAccessKeyId")
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise ResponseWorkflowError(404, "IncidentNotFound")
    if incident.status in {"resolved", "false_positive"}:
        raise ResponseWorkflowError(409, "IncidentIsClosed")

    target = _user_for_access_key(
        _related_events(db, incident.id),
        incident.account_id,
        access_key_id,
    )
    if target is None:
        raise ResponseWorkflowError(422, "AccessKeyNotObservedInIncidentEvidence")
    user_name, principal_arn = target
    response_action = ResponseAction(
        id=uuid4(),
        incident_id=incident.id,
        action_type="disable_access_key",
        account_id=incident.account_id,
        region=incident.region,
        target_principal_arn=principal_arn,
        target_user_name=user_name,
        target_access_key_id=access_key_id,
        reason=reason.strip(),
        status="pending_approval",
        dry_run=True,
        requested_by=actor.id,
    )
    db.add(response_action)
    db.flush()
    _audit(
        db,
        response_action,
        actor,
        "request_created",
        {"action_type": response_action.action_type, "incident_id": str(incident.id)},
    )
    db.commit()
    db.refresh(response_action)
    return response_action


def decide_response_action(
    db: Session,
    response_action: ResponseAction,
    actor: User,
    *,
    approve: bool,
    reason: str,
) -> ResponseAction:
    response_action = db.scalar(
        select(ResponseAction).where(ResponseAction.id == response_action.id).with_for_update()
    )
    if response_action is None:
        raise ResponseWorkflowError(404, "ResponseActionNotFound")
    if response_action.status != "pending_approval":
        raise ResponseWorkflowError(409, "ActionIsNotPendingApproval")
    if response_action.requested_by == actor.id:
        raise ResponseWorkflowError(409, "IndependentApprovalRequired")
    if actor.role not in _WRITE_ROLES:
        raise ResponseWorkflowError(403, "ApprovalRoleRequired")
    response_action.status = "approved" if approve else "rejected"
    response_action.approved_by = actor.id if approve else None
    response_action.approved_at = datetime.now(UTC) if approve else None
    _audit(
        db,
        response_action,
        actor,
        "approved" if approve else "rejected",
        {"reason": reason.strip()},
    )
    db.commit()
    db.refresh(response_action)
    return response_action


def execute_response_action(
    db: Session,
    response_action: ResponseAction,
    actor: User,
    settings: Settings,
    accounts: list[MonitoredAwsAccount],
) -> ResponseAction:
    response_action = db.scalar(
        select(ResponseAction).where(ResponseAction.id == response_action.id).with_for_update()
    )
    if response_action is None:
        raise ResponseWorkflowError(404, "ResponseActionNotFound")
    if response_action.status != "approved":
        raise ResponseWorkflowError(409, "ActionIsNotApproved")

    def block_execution(code: str) -> NoReturn:
        _audit(
            db,
            response_action,
            actor,
            "execution_blocked",
            {"code": code},
        )
        db.commit()
        raise ResponseWorkflowError(409, code)

    account = None
    if not settings.response_dry_run:
        if not settings.response_actions_enabled:
            block_execution("LiveResponseActionsDisabled")
        account = next(
            (
                configured
                for configured in accounts
                if configured.account_id == response_action.account_id
            ),
            None,
        )
        if account is None or account.response_role_arn is None:
            block_execution("SeparateResponseRoleNotConfigured")
        if response_action.target_user_name not in account.response_allowed_iam_users:
            block_execution("TargetUserNotInResponseAllowlist")

    now = datetime.now(UTC)
    response_action.executed_by = actor.id
    response_action.executed_at = now
    response_action.dry_run = settings.response_dry_run

    if settings.response_dry_run:
        response_action.status = "dry_run"
        response_action.result = {
            "operation": "iam:UpdateAccessKey",
            "target_user_name": response_action.target_user_name,
            "access_key_id": response_action.target_access_key_id,
            "requested_status": "Inactive",
            "executed": False,
        }
        response_action.error_code = None
        _audit(
            db,
            response_action,
            actor,
            "dry_run_executed",
            {"operation": "iam:UpdateAccessKey", "executed": "false"},
        )
        db.commit()
        db.refresh(response_action)
        return response_action

    try:
        disable_access_key(
            account,
            response_action.target_user_name,
            response_action.target_access_key_id,
        )
    except ResponseActionExecutionError as exc:
        response_action.status = "failed"
        response_action.error_code = exc.code[:128]
        response_action.result = {
            "operation": "iam:UpdateAccessKey",
            "executed": False,
        }
        _audit(
            db,
            response_action,
            actor,
            "execution_failed",
            {"error_code": response_action.error_code},
        )
        db.commit()
        db.refresh(response_action)
        return response_action

    response_action.status = "executed"
    response_action.error_code = None
    response_action.result = {
        "operation": "iam:UpdateAccessKey",
        "requested_status": "Inactive",
        "executed": True,
    }
    _audit(
        db,
        response_action,
        actor,
        "executed",
        {"operation": "iam:UpdateAccessKey", "status": "Inactive"},
    )
    db.commit()
    db.refresh(response_action)
    return response_action
