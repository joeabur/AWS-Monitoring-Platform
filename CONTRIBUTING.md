# Contributing

## Prerequisites

- Python 3.12+
- Node.js 22+
- Docker and Docker Compose v2.20+
- Terraform 1.10+ when changing infrastructure

## Setup

```bash
cp .env.example .env
python -m pip install -r backend/requirements-dev.txt
npm ci --prefix frontend
```

Set a unique `JWT_SECRET_KEY` before starting the API. Never commit local secrets.

## Quality gates

Run the complete local check from the repository root:

```bash
make check
```

Backend:

```bash
cd backend
ruff check app tests
ruff format --check app tests
python -m pytest
```

Frontend:

```bash
npm run typecheck --prefix frontend
npm run build --prefix frontend
```

Infrastructure:

```bash
terraform fmt -check -recursive infrastructure/terraform
terraform -chdir=infrastructure/terraform/modules/cloudtrail-event-pipeline init -backend=false
terraform -chdir=infrastructure/terraform/modules/cloudtrail-event-pipeline validate
```

## Change expectations

- Preserve existing API paths and response compatibility unless a migration is explicitly approved.
- Add focused tests for behavior changes and security boundaries.
- Keep AWS integration code read-only unless the change is an explicitly reviewed response workflow.
- Use parameterized SQL and validated Pydantic contracts for external inputs.
- Do not add secrets, AWS account data, or sensitive event payloads to fixtures or documentation.
- Run database migrations in a separate deployment job for production replicas.

## Pull requests

Describe the user-visible behavior, architecture, security impact, and test evidence. Link relevant
issues and include migration or rollback instructions when data or infrastructure is affected.
