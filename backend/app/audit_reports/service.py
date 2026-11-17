import hashlib
import json
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import AuditorFinding, AuditorReport
from app.schemas.audit_reports import AuditorReportInput


def import_auditor_report(
    db: Session,
    report: AuditorReportInput,
    imported_by: UUID,
) -> tuple[AuditorReport, int, bool]:
    serialized = json.dumps(
        report.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    fingerprint = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    existing = db.scalar(select(AuditorReport).where(AuditorReport.fingerprint == fingerprint))
    if existing is not None:
        return existing, 0, True

    record = AuditorReport(
        fingerprint=fingerprint,
        account_id=report.account_id,
        regions=report.regions,
        audit_profile=report.audit_profile,
        tool_name=report.tool["name"],
        tool_version=report.tool.get("version", "unknown")[:64],
        catalog_version=report.catalog_version,
        generated_at=report.generated_at,
        started_at=report.started_at,
        finding_count=len(report.findings),
        imported_by=imported_by,
    )
    try:
        with db.begin_nested():
            db.add(record)
            db.flush()
            db.add_all(
                [
                    AuditorFinding(
                        report_id=record.id,
                        report_generated_at=report.generated_at,
                        source_finding_id=finding.finding_id,
                        account_id=finding.account_id,
                        region=finding.region,
                        control_id=finding.control_id,
                        title=finding.title,
                        resource_id=finding.resource_id,
                        resource_type=finding.resource_type,
                        severity=finding.severity.value,
                        status=finding.status.value,
                        message=finding.message,
                        evidence=finding.evidence,
                        sources=finding.sources,
                        observed_at=finding.observed_at,
                        remediation=finding.remediation,
                        uncertainty=finding.uncertainty,
                        suppression=(
                            finding.suppression.model_dump(mode="json")
                            if finding.suppression is not None
                            else None
                        ),
                    )
                    for finding in report.findings
                ]
            )
            db.flush()
    except IntegrityError:
        existing = db.scalar(select(AuditorReport).where(AuditorReport.fingerprint == fingerprint))
        if existing is None:
            raise
        return existing, 0, True

    db.commit()
    db.refresh(record)
    return record, len(report.findings), False


def correlated_audit_findings(
    db: Session,
    account_id: str,
    resource_arns: list[str],
    *,
    limit: int = 100,
) -> list[AuditorFinding]:
    if not resource_arns:
        return []
    resource_ids = set(resource_arns)
    for resource_arn in resource_arns:
        if ":::" in resource_arn:
            resource_ids.add(resource_arn.rsplit(":::", 1)[1])
        if "/" in resource_arn:
            resource_ids.add(resource_arn.rsplit("/", 1)[1])

    records = db.scalars(
        select(AuditorFinding)
        .where(
            AuditorFinding.account_id == account_id,
            AuditorFinding.resource_id.in_(resource_ids),
        )
        .order_by(
            AuditorFinding.report_generated_at.desc(),
            AuditorFinding.observed_at.desc(),
            AuditorFinding.id,
        )
        .limit(limit * 10)
    ).all()
    latest: dict[tuple[str, str, str], AuditorFinding] = {}
    for record in records:
        key = (record.control_id, record.region, record.resource_id)
        latest.setdefault(key, record)
    return list(latest.values())[:limit]
