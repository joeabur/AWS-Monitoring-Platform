# Architecture

## Runtime components

```text
Browser / dashboard
        |
        v
Next.js frontend
        |
        v
FastAPI API (:8000)
  |- versioned HTTP routes
  |- Pydantic request/response schemas
  |- role-based authorization
  |- detection and incident services
  `- SQLAlchemy database access
        |
        v
PostgreSQL

AWS EventBridge / SQS
        |
        v
Python SQS worker
        |
        v
CloudTrail normalization -> detections -> alerts/incidents
```

The API and worker share application models and services, while deployment entry points remain
separate. The worker validates that production use has a PostgreSQL database and reports
per-message SQS batch failures.

## Backend organization

- `app/api`: versioned HTTP contracts and route dependencies.
- `app/core`: environment configuration and authentication primitives.
- `app/middleware`: request safeguards and response protections.
- `app/models`: SQLAlchemy persistence entities.
- `app/schemas`: Pydantic API models and validation.
- `app/detections`: rule catalog and detection evaluation.
- `app/incidents`: alert correlation and incident lifecycle.
- `app/ingestion`: event normalization, persistence, and SQS entry point.
- `app/integrations`: AWS read-only and bounded response integrations.
- `app/audit_reports`, `app/notifications`, `app/response`: feature services.
- `app/mcp`: opt-in, read-only MCP/AI tool definitions and incident/evidence context.
- `migrations`: reviewed Alembic schema revisions.
- `tests`: isolated offline unit and API tests.

## MCP and AI guardrails

The MCP integration is disabled by default and must be enabled explicitly with `MCP_ENABLED=true`.
It exposes incident listing/detail, filtered alert search, curated alert evidence, and guardrails
through authenticated JSON-RPC tools. It does not expose generic command execution, AWS credentials,
database access, secret configuration, response creation, response approval, or response execution.

AI systems and MCP clients must treat returned incident data as untrusted evidence. Any suggested
remediation remains advisory; live AWS writes require the existing separate evidence-bound,
role-separated, two-person approval, per-account allowlist, and explicit live-response workflow.
An administrator or security analyst should review all AI output before using it to make operational
decisions.

## Configuration

Configuration is environment-driven through Pydantic Settings. `.env.example` documents local
defaults; secrets must be supplied through protected environment variables or a secret manager.
Production startup rejects SQLite, weak JWT configuration, unsafe CORS origins, and PostgreSQL
connections without TLS mode.

## Trust boundaries

- Browser requests authenticate with bearer tokens; role dependencies enforce authorization.
- Login is additionally limited by an in-process fixed window. Production requires a shared ingress
  limiter.
- AWS monitoring credentials are read-only; response credentials are separate and opt-in.
- SQS, notification, database, and third-party integration failures must be contained by the
  responsible service and reported to an operator.

## Deployment constraints

PostgreSQL is the production database. Run migrations once as a deployment job before API replicas
start, and do not run migrations concurrently as application startup work in every replica. The
Docker images run as non-root users. Terraform in this repository is currently an opt-in event
pipeline module, not a complete production root stack.
