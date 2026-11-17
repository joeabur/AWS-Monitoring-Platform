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
| 2 — Ingestion (current) | CloudTrail normalization, durable event persistence/API, idempotency, SQS partial-batch worker, synthetic generator, opt-in EventBridge/SQS Terraform module |
| 3 — Detection | Versioned detection-as-code, initial rule library, thresholds/correlation, transparent risk score, test harness |
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
stable. Phases 1 and 2 deliberately contain no direct AWS polling, live AWS connection, detection
rules, or mock dashboard counts. The initial UI reports actual API/database health and explicitly
says when monitoring is not yet connected. Phase 2's synthetic generator creates clearly marked
local records.

## Milestones and acceptance criteria

### Phase 1 — Foundation (complete)

- [x] Local application, PostgreSQL migration, authentication, role checks, service health, and live
  health dashboard.

### Phase 2 — Event ingestion (current)

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

## Repository layout

```text
backend/
  app/
    api/                 Versioned API routes and authentication
    core/                Settings and token/password security
    ingestion/           CloudTrail normalization, persistence, and SQS worker
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

The dashboard currently reports application/database health only. There are no AWS accounts,
alerts, or incidents until later phases are implemented. Phase 2 events can be populated locally
with synthetic-only data:

```bash
docker compose exec api python -m app.scripts.generate_sample_events --count 8
```

Ingest or query normalized events using the authenticated API:

```text
POST /api/v1/events/ingest
GET  /api/v1/events?account_id=111122223333&region=us-east-1&limit=50&offset=0
GET  /api/v1/events/{event_id}
```

The ingest route accepts a CloudTrail record or EventBridge event envelope and requires an
Administrator or Security Analyst token. Read access requires authentication. The local synthetic
generator inserts into the configured database and marks records as synthetic; do not confuse those
records with AWS telemetry.

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

No AWS credentials are needed for tests. Live AWS collector deployment is not part of Phase 2.

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
- Detection rules, alerts, incident handling, GuardDuty, and notification delivery remain future
  phases. The event API and SQS worker persist normalized events only; they do not declare incidents.
