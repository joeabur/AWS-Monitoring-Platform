# AWS Cloud Security Monitoring Platform

Continuous AWS threat monitoring and incident response, designed to complement—not replace—the
independent [AWS Security Auditing Tool](https://github.com/joeabur/AWS-security-auditing-tool).

## Responsibilities

- **AWS Security Auditing Tool:** point-in-time, read-only posture assessment against its 41 controls;
  produces evidence-backed reports.
- **This platform:** continuous event ingestion, threat detections, alerting, and incident workflows.
  Later it will ingest audit reports so ongoing activity can be correlated with known weaknesses.

The auditor's current JSON report uses `schema_version: 1`, with account and region context plus
`findings[]` entries containing `finding_id`, `control_id`, `resource_id`, `resource_type`,
`severity`, `status`, `message`, `evidence`, `observed_at`, and `remediation`. The planned importer
will validate that envelope, retain source report/finding identifiers and assessment timestamps,
and map resource identifiers without changing or calling the auditor. Its sample report contains a
masked account ID; the importer must preserve that uncertainty rather than inventing the full ID.
No auditor dependency or API is required for this platform.

## Architecture and implementation plan

The intended production data path is **AWS services → EventBridge → SQS (+ DLQ) → isolated event
worker → normalization/detection/correlation → PostgreSQL → FastAPI → dashboard/notifications**.
SQS buffers bursts and permits retries; a dead-letter queue preserves repeatedly failing messages.
FastAPI serves the analyst UI and APIs, not the AWS event polling loop. AWS access will use the
standard boto3 credential chain locally and STS-assumed, read-only roles for monitored accounts.
Response actions, if enabled in a later phase, will use a separate narrowly-scoped role.

| Phase | Deliverable |
|---|---|
| 1 — Foundation (complete) | FastAPI service, PostgreSQL schema/migration, role-based token authentication, health endpoint, Compose, live health UI |
| 2 — Ingestion (complete) | CloudTrail normalization, durable event persistence/API, idempotency, SQS partial-batch worker, synthetic generator, opt-in EventBridge/SQS Terraform module |
| 3 — Detection (current) | 15 versioned rules, thresholds/correlation, persisted deduplicated alerts, explicit risk-score basis, rule test API and synthetic scenarios |
| 4 — Incidents | Evidence, incident lifecycle, timeline, assignment, notes, audit trail |
| 5 — AWS integrations | STS multi-account/region discovery, GuardDuty, Security Hub, AWS Config; mock-backed tests |
| 6 — Operations UI and notifications | Real-event metrics, filters, Slack/Teams/email routing, delivery health |
| 7 — Auditor integration | Schema-v1 JSON report import and correlation with current events |
| 8 — Controlled response | Detection-only by default; dry-run, analyst approval, separate permissions, audited playbooks |
| 9 — Production readiness | Threat/security review, load/reliability tests, CI, Terraform and operational guides |

### MVP boundary

The MVP is CloudTrail event ingestion, normalization, detection and incident evidence, with GuardDuty
as the first enrichment source. Security Hub, Config, correlation with imported audit findings,
notifications, and response automation follow only after the ingestion and incident contracts are
stable. Phases 1–3 deliberately contain no direct AWS polling, live AWS connection, or mock
dashboard counts. The initial UI reports actual API/database health and explicitly says when
monitoring is not yet connected. The synthetic generator creates clearly marked local records.

## Milestones and acceptance criteria

### Phase 1 — Foundation (complete)

- [x] Local application, PostgreSQL migration, authentication, role checks, service health, and live
  health dashboard.

### Phase 2 — Event ingestion (complete)

- [x] Normalize CloudTrail records and EventBridge envelopes; normalize timestamps to UTC and reject
  ambiguous timestamps or missing account/event identifiers.
- [x] Persist selected normalized fields and a filtered detail subset, redact obvious secret-bearing
  keys, and deduplicate by account, region, and CloudTrail event ID.
- [x] Provide authenticated ingest/read APIs with account, region, name, and time filters plus
  pagination; only analysts and administrators may ingest.
- [x] Add an SQS Lambda handler that reports per-message failures for retry, and provide separate
  delivery and processing DLQs in opt-in Terraform.
- [x] Generate local synthetic CloudTrail records with an explicit synthetic marker.
- [x] Routine validation does not require AWS credentials or paid AWS services.

### Phase 3 — Detection engineering (complete)

- [x] Versioned detection library covers 15 AWS activity and exposure scenarios, with MITRE
  mappings where applicable.
- [x] Evaluate new events during ingestion; thresholded failures correlate within documented
  windows and by source/principal where appropriate.
- [x] Persist deduplicated alerts with evidence-event references, relative risk score explanation,
  recommended investigation steps, and response guidance.
- [x] Provide authenticated rule inventory, event test endpoint, alert search/filter/pagination, and
  alert evidence endpoint.
- [x] Keep allowlist-dependent rules disabled until their required environment configuration exists.
- [x] Test expected positive/negative scenarios and ensure rule tests do not persist synthetic events.

Scores are rule-defined prioritization values from 0–100, **not probabilities or definitive risk**.
Rule severity and score basis are visible on every alert; score values can be adjusted in the
versioned rule definitions. Rule definitions live in
[`backend/app/detections/rules.py`](./backend/app/detections/rules.py); updates are reviewed and
versioned as code.

## Repository layout

```text
backend/
  app/
    api/                 Versioned API routes and authentication
    core/                Settings and token/password security
    ingestion/           CloudTrail normalization, persistence, and SQS worker
    detections/          Versioned rule catalog, correlation, and evaluator
    models/              SQLAlchemy entities
    schemas/             Validated API contracts
    database.py          Database engine and session dependency
  migrations/            Alembic configuration and revisions
  scripts/               Local administrative utilities
  tests/                 Offline unit and API tests
frontend/
  app/                   Next.js dashboard
  Dockerfile
infrastructure/terraform/modules/
  cloudtrail-event-pipeline/  Opt-in EventBridge/SQS resources
docker-compose.yml       Local PostgreSQL + API + frontend
.env.example             Local configuration template (no credentials)
```

## Run locally

Requirements: Docker Compose (or Python 3.12+ and Node.js 20+ for running services separately).

```bash
cp .env.example .env
python -c 'import secrets; print(secrets.token_hex(32))'
# Put that output in .env as JWT_SECRET_KEY.
docker compose up --build
```

Open the dashboard at <http://localhost:3000>; API docs are at <http://localhost:8000/docs> and
health at <http://localhost:8000/api/v1/health>. There is intentionally no default administrator.
After Compose is running, create the first administrator interactively:

```bash
docker compose exec api python -m app.scripts.create_admin
```

The dashboard currently reports application/database health only. There are no AWS accounts
connected or incident workflows yet. Phase 2 events can be populated locally with synthetic-only
data, which can generate Phase 3 alerts:

```bash
docker compose exec api python -m app.scripts.generate_sample_events --count 8
```

Ingest or query normalized events using the authenticated API:

```text
POST /api/v1/events/ingest
GET  /api/v1/events?account_id=111122223333&region=us-east-1&limit=50&offset=0
GET  /api/v1/events/{event_id}
GET  /api/v1/detections
POST /api/v1/detections/{rule_id}/test
GET  /api/v1/alerts?severity=high&status=open&limit=50&offset=0
GET  /api/v1/alerts/{alert_id}
```

The ingest route accepts a CloudTrail record or EventBridge event envelope and requires an
Administrator or Security Analyst token. Read access requires authentication. The local synthetic
generator inserts into the configured database and marks records as synthetic; do not confuse those
records with AWS telemetry.

Newly ingested events are evaluated against the rule library and can create or update an alert in
the same database transaction. Replays of the same AWS event do not re-evaluate or duplicate its
alert. Failed console login and denied API rules use five matching events in ten minutes; matching
is grouped by source IP or principal. Access-key correlation is limited to the configured one-hour
window. Rule test requests do not store the submitted event or produce alerts.

Rules that need an expected-user, trusted-CIDR, or sensitive-resource list stay disabled while the
corresponding `.env` value is empty. Configure comma-separated values in `EXPECTED_IAM_USERS`,
`TRUSTED_IP_CIDRS`, and `SENSITIVE_RESOURCE_ARNS`; invalid CIDRs fail configuration validation.
GuardDuty findings and Config compliance notifications can be normalized and tested through the
ingest API, but the Terraform SQS module currently routes CloudTrail management events only. A
GuardDuty/Config AWS delivery integration still needs to be configured and verified separately.

The event worker is packaged with `backend/Dockerfile.worker`, using
`app.ingestion.worker.lambda_handler`. For SQS-triggered Lambda, enable `ReportBatchItemFailures` on the event-source mapping so failed records are retried
independently. The opt-in Terraform module at
[`infrastructure/terraform/modules/cloudtrail-event-pipeline`](./infrastructure/terraform/modules/cloudtrail-event-pipeline)
creates an account-filtered CloudTrail management-event rule, encrypted SQS queue, processor DLQ,
and EventBridge delivery DLQ. It does not deploy or wire the Lambda consumer. Cross-account event
forwarding and account trust are separate setup. No Terraform is applied automatically.

To run backend tests locally:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r backend/requirements-dev.txt
cd backend && python -m pytest
```

No AWS credentials are needed for tests. Live AWS collector deployment is not part of Phase 3.

## AWS access, permissions, and cost approach

Nothing in this milestone provisions or calls AWS. Future monitored accounts will grant a dedicated
platform role to the collector account using an explicit trust relationship (external ID where
appropriate); collection credentials will be temporary STS credentials. Local use will honor the
AWS credential chain. Discovery and integrations will be separately scoped and read-only; likely
read actions include `sts:GetCallerIdentity`, `ec2:DescribeRegions`, CloudTrail lookup/read APIs,
GuardDuty list/get APIs, Security Hub finding reads, and AWS Config read APIs. Event delivery also
requires narrowly scoped EventBridge target permissions and SQS queue resource policies. Exact
actions will be generated from implemented calls and reviewed before publishing a policy. No
response permissions will be combined with monitoring permissions.

**Cost:** Local development and tests cost **$0 in AWS** (containers run locally); local
compute/storage are outside AWS billing. The Terraform module is opt-in and not deployed. Future
costs depend on account/region count, CloudTrail
data-event volume, GuardDuty/Security Hub/Config enablement and billing plans, EventBridge/SQS
throughput, retention, and database sizing. Those metered services can incur charges even when the
application is idle. Before any deployment, a region- and volume-specific estimate, budget alarm,
explicit service enablement list, and destroy procedure are required. No cost estimate for that
future deployment is represented as a quote or included in this repository yet.

## Security notes and current limitations

- Keep `.env` local; set a unique random JWT secret. Production secrets belong in a secret manager.
- The first administrator is provisioned out-of-band; there is no public user registration.
- This foundation has no application rate limiter, SSO/MFA, event retention policy, or production
  deployment hardening yet. Do not expose it directly to the internet.
- The API uses bearer tokens (no browser cookie session); production frontend hosting should use
  TLS and a reviewed token/session strategy.
- Direct AWS event delivery/deployment has not been configured or verified in a real AWS account.
  The Terraform module defines a queue/rule pattern; it is not a deployed AWS integration.
- The detection engine generates alerts but does not manage incidents, analyst acknowledgements,
  assignments, or investigation notes; those are Phase 4.
- GuardDuty and Config EventBridge records can be normalized for detection, but no AWS delivery rule
  for those sources has been deployed.
- There are no notifications, response actions, or live detection dashboards yet.
