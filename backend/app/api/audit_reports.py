from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import func, or_, select

from app.api.dependencies import CurrentUser, Database, require_roles
from app.audit_reports.service import import_auditor_report
from app.models import AuditorFinding, AuditorReport, User
from app.schemas.audit_reports import (
    AuditFindingPage,
    AuditFindingRead,
    AuditFindingSeverity,
    AuditFindingStatus,
    AuditorReportInput,
    AuditReportDetail,
    AuditReportImportResult,
    AuditReportPage,
    AuditReportRead,
)
from app.schemas.auth import UserRole

router = APIRouter(tags=["auditor reports"])
_WRITE_ROLES = (UserRole.ADMINISTRATOR, UserRole.SECURITY_ANALYST)


@router.post(
    "/api/v1/audit-reports/import",
    response_model=AuditReportImportResult,
    status_code=status.HTTP_201_CREATED,
)
def import_report(
    payload: AuditorReportInput,
    db: Database,
    response: Response,
    actor: Annotated[User, Depends(require_roles(*_WRITE_ROLES))],
) -> AuditReportImportResult:
    report, findings_imported, duplicate = import_auditor_report(db, payload, actor.id)
    if duplicate:
        response.status_code = status.HTTP_200_OK
    return AuditReportImportResult(
        report=AuditReportRead.model_validate(report),
        findings_imported=findings_imported,
        duplicate=duplicate,
    )


@router.get("/api/v1/audit-reports", response_model=AuditReportPage)
def list_reports(
    db: Database,
    _: CurrentUser,
    account_id: Annotated[str | None, Query(min_length=1, max_length=64)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AuditReportPage:
    filters = [AuditorReport.account_id == account_id] if account_id is not None else []
    total = db.scalar(select(func.count()).select_from(AuditorReport).where(*filters)) or 0
    records = db.scalars(
        select(AuditorReport)
        .where(*filters)
        .order_by(AuditorReport.generated_at.desc(), AuditorReport.id)
        .limit(limit)
        .offset(offset)
    ).all()
    return AuditReportPage(
        items=[AuditReportRead.model_validate(record) for record in records],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/api/v1/audit-reports/{report_id}", response_model=AuditReportDetail)
def get_report(
    report_id: UUID,
    db: Database,
    _: CurrentUser,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AuditReportDetail:
    report = db.get(AuditorReport, report_id)
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit report not found")
    filters = [AuditorFinding.report_id == report.id]
    total = db.scalar(select(func.count()).select_from(AuditorFinding).where(*filters)) or 0
    findings = db.scalars(
        select(AuditorFinding)
        .where(*filters)
        .order_by(AuditorFinding.control_id, AuditorFinding.resource_id, AuditorFinding.id)
        .limit(limit)
        .offset(offset)
    ).all()
    return AuditReportDetail(
        report=AuditReportRead.model_validate(report),
        findings=[AuditFindingRead.model_validate(finding) for finding in findings],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/api/v1/audit-findings", response_model=AuditFindingPage)
def list_audit_findings(
    db: Database,
    _: CurrentUser,
    account_id: Annotated[str | None, Query(min_length=1, max_length=64)] = None,
    region: Annotated[str | None, Query(min_length=1, max_length=64)] = None,
    control_id: Annotated[str | None, Query(pattern=r"^[A-Z]{2,4}-\d{3}$")] = None,
    resource_id: Annotated[str | None, Query(min_length=1, max_length=2048)] = None,
    finding_status: Annotated[AuditFindingStatus | None, Query(alias="status")] = None,
    severity: AuditFindingSeverity | None = None,
    search: Annotated[str | None, Query(min_length=1, max_length=256)] = None,
    report_id: UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AuditFindingPage:
    filters = []
    if account_id is not None:
        filters.append(AuditorFinding.account_id == account_id)
    if region is not None:
        filters.append(AuditorFinding.region == region.lower())
    if control_id is not None:
        filters.append(AuditorFinding.control_id == control_id)
    if resource_id is not None:
        filters.append(AuditorFinding.resource_id == resource_id)
    if finding_status is not None:
        filters.append(AuditorFinding.status == finding_status.value)
    if severity is not None:
        filters.append(AuditorFinding.severity == severity.value)
    if report_id is not None:
        filters.append(AuditorFinding.report_id == report_id)
    if search is not None:
        pattern = f"%{search}%"
        filters.append(
            or_(
                AuditorFinding.title.ilike(pattern),
                AuditorFinding.message.ilike(pattern),
                AuditorFinding.control_id.ilike(pattern),
                AuditorFinding.resource_id.ilike(pattern),
            )
        )

    total = db.scalar(select(func.count()).select_from(AuditorFinding).where(*filters)) or 0
    records = db.scalars(
        select(AuditorFinding)
        .where(*filters)
        .order_by(
            AuditorFinding.report_generated_at.desc(),
            AuditorFinding.observed_at.desc(),
            AuditorFinding.id,
        )
        .limit(limit)
        .offset(offset)
    ).all()
    return AuditFindingPage(
        items=[AuditFindingRead.model_validate(record) for record in records],
        total=total,
        limit=limit,
        offset=offset,
    )
