# Operations and deployment readiness

This guide covers safe local operation and the checks required before a production deployment.
The repository includes an opt-in production Terraform environment, but no AWS resources have been
deployed or validated in a live account.

## Local verification

The local stack uses Docker Compose and a local PostgreSQL container. Set a random
`JWT_SECRET_KEY` in `.env`, then run:

```bash
docker compose config
docker compose build
docker compose up --wait
```

Compose runs Alembic migrations during the single local API startup. The API and frontend
containers run as non-root users. The API image supports an opt-out migration switch for production
deployments; do not allow every API replica to run schema migrations concurrently.

Use `/api/v1/health/live` for process liveness and `/api/v1/health/ready` for database readiness.
The existing `/api/v1/health` endpoint remains available as a backward-compatible combined check.
API responses include `X-Request-ID`; supply an ID with `X-Request-ID` for traceable support
requests or let the service generate and return a bounded UUID correlation ID.
The API container uses liveness for its image health check; Compose uses database readiness.

Login requests are limited to 10 attempts per client IP per 60-second fixed window, per API process.
The limiter uses the socket peer address and deliberately does not trust `X-Forwarded-For` directly.
It is a best-effort local safeguard, not distributed brute-force protection.

## Event retention

The retention command uses a 90-day cutoff by default. It deletes expired raw CloudTrail event rows
and removes their IDs from alert evidence references, including references on open incidents. The
event details will no longer be available in the application after pruning. Incident and response
audit history remains in PostgreSQL and is exported daily to a versioned S3 bucket with Object Lock
COMPLIANCE retention in the production Terraform environment.

Run the command from the backend environment. It reports eligible rows and references to be removed
without changing data unless `--apply` is passed:

```bash
cd backend
python -m app.scripts.prune_events --older-than-days 90
python -m app.scripts.prune_events --older-than-days 90 --apply
```

Review the dry-run output and backup/retention approvals before applying. Schedule the command
through a single controlled maintenance job, not every API replica. Candidate events are scanned
in batches within one database transaction and deletion rolls back on failure; alert evidence
references are updated before expired rows are deleted. Retention is based on event time; delayed
arrivals older than the cutoff may be eligible immediately.

The production stack runs `app.scripts.export_audit` daily before the raw-event pruning task. The
export includes incident and response-action audit entries, marks each row archived only after a
successful S3 write, and leaves PostgreSQL audit history intact. Row-level markers ensure that an
audit record inserted during an export is still picked up by the next run. A failure after the S3
write but before the database commit can cause a duplicate immutable archive object/version; it does not
advance archive markers or lose the audit rows. The Object Lock period
defaults to 90 days; changing or deleting an object in COMPLIANCE mode is prohibited until its
retention date. The archive's S3 lifecycle policy expires locked objects after the retention period
plus one day. Configure the optional `alarm_email` to receive scheduled task failure notifications.
Test restore and verify archive integrity as part of the production recovery exercise.

## Release and migration procedure

The GitHub Actions workflow validates backend tests/lint, frontend type/build, and Terraform
format/validation on a fixed Ubuntu runner. Third-party actions are pinned to immutable commit
SHAs, with release tags in comments so Dependabot can propose updates. Review action updates for
permissions and behavior before merging. CI does not publish images, deploy infrastructure, or
perform live AWS tests. Build and publish signed/versioned images through a separately approved
release pipeline.

For production, set `MIGRATIONS_ON_STARTUP=false` on API replicas. Run `alembic upgrade head` once
as a deployment job using the same API image, database secret, network, and release version before
rolling out the API. Take and verify a database backup before schema changes. The migrations are
reviewed schema changes; even where a downgrade function exists, a downgrade may discard data. A
failed migration should stop rollout and be recovered using a tested database restore or a reviewed
forward fix, not by guessing at a downgrade.

## Minimum production gates

- Put the frontend and API behind TLS termination and an authenticated ingress. Restrict CORS to
  the exact frontend origin; never expose the development Compose database port publicly.
- Set `ENVIRONMENT=production`. Startup rejects SQLite and non-HTTPS, non-exact, or localhost CORS
  origins and PostgreSQL URLs without `sslmode=require`, `verify-ca`, or `verify-full` in this
  mode. Prefer `verify-full` with the database provider's trusted CA bundle. These configuration
  guards are not a substitute for TLS termination or network/database access controls.
- Store `JWT_SECRET_KEY`, database credentials, notification secrets, and AWS role external IDs in a
  secret manager. Rotate them under an approved procedure; do not place secrets in image layers,
  logs, Terraform state, or source control.
- Production Terraform configures Cognito OIDC with required software-token MFA and administrative
  user creation. Keep application roles mapped to stable Cognito `sub` values and provision them
  only through the reviewed administrative workflow. The app does not provide a distributed rate
  limiter; configure per-user/IP request limits at the ingress before public exposure.
  The built-in 10-per-minute login limiter is in-process only and must not be treated as distributed
  protection. Behind a proxy, configure Uvicorn `FORWARDED_ALLOW_IPS` to the exact trusted proxy
  addresses/CIDRs; the proxy must strip client-supplied forwarding headers. Keep a shared ingress
  limiter enabled regardless.
- Use a private, encrypted PostgreSQL deployment with encrypted backups, tested restore procedures,
  and a defined retention/deletion policy. The production environment uses private multi-AZ RDS and
  Secrets Manager-managed credentials. Its scheduled retention job removes event evidence beyond
  the configured period; confirm that this behavior meets legal and operational requirements.
- Configure CloudTrail/EventBridge/SQS and the worker independently. Enable SQS partial batch
  failure reporting, keep queue visibility at least six times the worker timeout plus batching
  window, alarm on queue age/depth and both DLQs, and rehearse safe DLQ redrive.
- Keep monitoring collection read-only. Configure response role trust and permissions separately;
  leave response disabled/dry-run until the approval path, target allowlist, rollback procedure, and
  incident owner are reviewed.
- Keep `MCP_ENABLED=false` unless an authenticated MCP/AI client is explicitly required. The MCP
  interface is read-only and must not be used to execute AWS actions or issue generic commands.
  Review AI-produced recommendations as untrusted evidence, preserve source traceability, and route
  any remediation through the controlled response workflow.
- Test external backups, restore, alert routing, credential rotation, and a rollback exercise in an
  isolated environment before accepting production events.

## Operational signals and first response

Continuously monitor API/worker errors, database connectivity and capacity, SQS oldest-message age
and visible/in-flight counts, both DLQ counts, and notification delivery failures. Compare source
CloudTrail delivery volume with processed-event counts; integration health is the latest observed
check, not proof that collection is complete. Page on sustained ingestion delay or any unexpected
DLQ growth.

For ingestion failure: preserve queue and DLQ messages, stop risky changes, inspect structured
worker/API logs for request IDs and sanitized error codes, correct the root cause, and replay a small
verified DLQ sample before bulk redrive. For a database incident: stop writers, preserve an encrypted
snapshot, restore to an isolated instance, verify migration head and record counts, then switch
traffic using the database provider's approved procedure. Never discard failed messages or database
evidence before incident review.

For an incident response action, verify the linked event evidence, account, key owner, and current
business impact; obtain a second-person approval; execute only from an Administrator identity; and
record follow-up/rollback decisions. A key disable may interrupt workloads and reactivation is a
separate manual decision. Do not treat a response action as a substitute for credential rotation
and compromise investigation.

## AWS cost and teardown gate

Local tests and local Docker development make no AWS API calls and create no AWS charges. Production
cost cannot be responsibly quoted from this repository alone. Before any apply, estimate the actual
regions, account count, CloudTrail management/data event volume, GuardDuty/Security Hub/Config plans,
EventBridge/SQS requests and retention, database sizing/backup retention, log ingestion, and
egress. Add a budget and billing alarm, record an owner and monthly cap, and get approval. No
Terraform apply is part of CI or local startup.

The production Terraform environment and event-pipeline module are opt-in. Before deployment, review
the plan and policies in an
isolated account, save the plan for review, confirm the expected AWS cost, and document the specific
calling stack. Teardown must destroy the calling stack, then verify queues/rules/policies are gone;
review and preserve DLQ messages before removing their queues. This module does not create the
database, worker, worker execution role, alarms, or cross-account event-bus forwarding.

## Readiness gaps

Production use still requires a deployed/tested AWS environment, ingress rate limiting, load/soak
testing against stated volume targets, backup/restore and archive-integrity drills, and an
independent security assessment. The local login limiter is not a substitute for shared ingress
throttling. The CI checks are not a penetration test or a cloud integration test.
