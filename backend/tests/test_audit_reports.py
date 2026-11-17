from copy import deepcopy

from app.scripts.generate_sample_events import generate_sample_event


def _bearer(client, email: str = "analyst@example.com") -> dict[str, str]:
    login = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "correct-horse-battery"},
    )
    assert login.status_code == 200
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def _report(
    *,
    account_id: str = "********3333",
    finding_account_id: str | None = None,
    resource_id: str = "vol-0a1b2c3d4e5f60002",
    status: str = "FAIL",
    generated_at: str = "2026-10-16T12:00:00Z",
) -> dict[str, object]:
    account = finding_account_id or account_id
    return {
        "schema_version": 1,
        "tool": {"name": "aws-security-auditing-tool", "version": "0.1.0"},
        "catalog_version": "2026.10.1",
        "generated_at": generated_at,
        "started_at": generated_at,
        "account_id": account_id,
        "regions": ["us-east-1"],
        "audit_profile": "test",
        "controls_evaluated": ["EBS-002"],
        "summary": {"total_findings": 1, "by_status": {status: 1}},
        "api_actions": {"ec2:DescribeVolumes": 1},
        "warnings": [],
        "disclaimer": "Point-in-time assessment.",
        "findings": [
            {
                "finding_id": "finding-ebs-1",
                "control_id": "EBS-002",
                "title": "EBS volumes are encrypted",
                "account_id": account,
                "region": "us-east-1",
                "resource_id": resource_id,
                "resource_type": "AWS::EC2::Volume",
                "severity": "medium",
                "status": status,
                "message": f"Volume assessment: {status}.",
                "evidence": {"Encrypted": status == "PASS"},
                "sources": ["ec2:DescribeVolumes"],
                "observed_at": generated_at,
                "remediation": "Replace the volume with an encrypted volume.",
                "uncertainty": [],
                "suppression": None,
            }
        ],
    }


def test_import_is_idempotent_preserves_masked_account_and_enforces_writer_role(client) -> None:
    headers = _bearer(client)
    report = _report()

    imported = client.post("/api/v1/audit-reports/import", json=report, headers=headers)
    duplicate = client.post("/api/v1/audit-reports/import", json=report, headers=headers)
    findings = client.get(
        "/api/v1/audit-findings?resource_id=vol-0a1b2c3d4e5f60002",
        headers=headers,
    )
    report_detail = client.get(
        f"/api/v1/audit-reports/{imported.json()['report']['id']}",
        headers=headers,
    )
    viewer_import = client.post(
        "/api/v1/audit-reports/import",
        json=_report(generated_at="2026-10-17T12:00:00Z"),
        headers=_bearer(client, "viewer@example.com"),
    )

    assert imported.status_code == 201
    assert imported.json()["duplicate"] is False
    assert imported.json()["findings_imported"] == 1
    assert imported.json()["report"]["account_id"] == "********3333"
    assert duplicate.status_code == 200
    assert duplicate.json()["duplicate"] is True
    assert duplicate.json()["findings_imported"] == 0
    assert findings.status_code == 200
    assert findings.json()["total"] == 1
    assert findings.json()["items"][0]["severity"] == "medium"
    assert report_detail.status_code == 200
    assert report_detail.json()["findings"][0]["source_finding_id"] == "finding-ebs-1"
    assert viewer_import.status_code == 403

    invalid = deepcopy(report)
    invalid["schema_version"] = 2
    assert (
        client.post("/api/v1/audit-reports/import", json=invalid, headers=headers).status_code
        == 422
    )


def test_incident_correlates_latest_matching_audit_finding_and_dashboard_displays_it(
    client,
) -> None:
    headers = _bearer(client)
    event = generate_sample_event(2)
    event["detail"]["userIdentity"] = {
        "type": "Root",
        "principalId": "111122223333",
        "arn": "arn:aws:iam::111122223333:root",
    }
    ingested = client.post("/api/v1/events/ingest", json=event, headers=headers)
    assert ingested.status_code == 200
    assert ingested.json()["alert_ids"]

    masked_report = _report(
        resource_id="sg-demo",
        generated_at="2026-10-18T12:00:00Z",
    )
    first_report = _report(
        account_id="111122223333",
        finding_account_id="111122223333",
        resource_id="sg-demo",
        generated_at="2026-10-16T12:00:00Z",
    )
    latest_report = _report(
        account_id="111122223333",
        finding_account_id="111122223333",
        resource_id="sg-demo",
        status="PASS",
        generated_at="2026-10-17T12:00:00Z",
    )
    assert (
        client.post("/api/v1/audit-reports/import", json=masked_report, headers=headers).status_code
        == 201
    )
    assert (
        client.post("/api/v1/audit-reports/import", json=first_report, headers=headers).status_code
        == 201
    )
    failing_dashboard = client.get(
        "/api/v1/dashboard/summary?account_id=111122223333",
        headers=headers,
    )
    assert failing_dashboard.json()["metrics"]["active_audit_failures"] == 1, (
        failing_dashboard.json()
    )
    assert (
        client.post("/api/v1/audit-reports/import", json=latest_report, headers=headers).status_code
        == 201
    )

    incidents = client.get("/api/v1/incidents?account_id=111122223333", headers=headers)
    incident_id = incidents.json()["items"][0]["id"]
    detail = client.get(f"/api/v1/incidents/{incident_id}", headers=headers)
    dashboard = client.get(
        "/api/v1/dashboard/summary?account_id=111122223333",
        headers=headers,
    )

    assert detail.status_code == 200
    assert len(detail.json()["audit_findings"]) == 1
    assert detail.json()["audit_findings"][0]["status"] == "PASS"
    assert detail.json()["audit_findings"][0]["resource_id"] == "sg-demo"
    assert dashboard.status_code == 200
    assert dashboard.json()["latest_audit_report"]["account_id"] == "111122223333"
    assert dashboard.json()["metrics"]["active_audit_failures"] == 0
    assert dashboard.json()["audit_findings"] == []
