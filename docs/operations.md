# Operations and deployment readiness

This guide covers safe local operation and the checks required before a production deployment.
It does not describe a ready-to-apply production stack: no AWS resources have been deployed, and
the repository does not include a production root Terraform configuration.

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
- The app does not provide SSO/MFA or an application rate limiter. Require enterprise identity
  controls at the ingress and configure per-user/IP request limits there before public exposure.
- Use a private, encrypted PostgreSQL deployment with least-privilege database credentials,
  encrypted backups, tested restore procedures, and a defined retention/deletion policy. The
  application currently has no automatic event-retention job; database growth is unbounded.
- Configure CloudTrail/EventBridge/SQS and the worker independently. Enable SQS partial batch
  failure reporting, keep queue visibility at least six times the worker timeout plus batching
  window, alarm on queue age/depth and both DLQs, and rehearse safe DLQ redrive.
- Keep monitoring collection read-only. Configure response role trust and permissions separately;
  leave response disabled/dry-run until the approval path, target allowlist, rollback procedure, and
  incident owner are reviewed.
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

The event-pipeline Terraform module is opt-in. Before deployment, review its plan and policies in an
isolated account, save the plan for review, confirm the expected AWS cost, and document the specific
calling stack. Teardown must destroy the calling stack, then verify queues/rules/policies are gone;
review and preserve DLQ messages before removing their queues. This module does not create the
database, worker, worker execution role, alarms, or cross-account event-bus forwarding.

## Readiness gaps

Production use still requires a deployed/tested AWS environment, production Terraform root stack,
application SSO/MFA or reviewed session architecture, ingress rate limiting, event retention,
load/soak testing against stated volume targets, backup/restore drills, and an independent security
assessment. The CI checks are not a penetration test or a cloud integration test.
