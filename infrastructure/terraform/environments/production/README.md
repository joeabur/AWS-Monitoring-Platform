# Production AWS environment

This is an opt-in production stack for ECS Fargate (API, frontend, retention, and audit export), RDS
PostgreSQL, Cognito MFA/OIDC, EventBridge/SQS, the SQS Lambda worker, CloudWatch metrics/alarms, and
scheduled retention. It creates a new VPC, two NAT gateways, an internet-facing ALB, a multi-AZ
database, and AWS resources that can incur ongoing charges. Nothing is deployed by CI or local
development.

## Required inputs

Copy `terraform.tfvars.example` to a protected `terraform.tfvars` and set:

- an ACM certificate in `aws_region` that covers `app_domain_name`;
- immutable API, frontend, and Lambda-compatible worker image URIs in ECR;
- a unique Cognito hosted-domain prefix;
- monitored AWS account IDs and (preferably) dedicated read-only role ARNs;
- an optional Route 53 zone ID and alarm email.

Build the frontend image from `frontend/Dockerfile`; it reads Cognito and same-origin API settings
from runtime environment variables, so it does not need Cognito IDs at image-build time. Use the
worker image built from `backend/Dockerfile.worker`.

The Cognito pool is configured for administratively-created users and required software-token MFA.
Application roles remain separately provisioned in PostgreSQL and are mapped to stable Cognito `sub`
identifiers. The public user-pool client uses authorization code flow and PKCE; the API accepts only
RS256 Cognito access tokens for the configured issuer and client.

## State and deployment

Configure an encrypted, versioned remote Terraform state backend with locking before initializing
this environment. Do not use shared local state for production. Review the full plan and a
region/account-specific cost estimate; the two NAT gateways, multi-AZ RDS, ALB, log storage, and
data ingestion are billable.

```bash
terraform init \
  -backend-config="bucket=<versioned-state-bucket>" \
  -backend-config="key=aws-monitoring-platform/production/terraform.tfstate" \
  -backend-config="region=<state-bucket-region>" \
  -backend-config="encrypt=true" \
  -backend-config="use_lockfile=true"
terraform fmt -check
terraform validate
terraform plan -out=production.tfplan
terraform show production.tfplan
```

Apply only after approval. After RDS and ECS infrastructure exists, run the API task definition once
with command override `alembic upgrade head`; application replicas deliberately do not run
migrations at startup. The API target remains unready until the migration completes.

Create each Cognito user administratively, require MFA enrollment, retrieve that user's stable
`sub`, and provision the corresponding application role with the reviewed user-provisioning command.
Never enable public self-registration or assign administrator roles from untrusted claims.

## Security and operations

- The database is private, encrypted, multi-AZ, and uses an RDS-managed password in Secrets Manager.
  API, worker, retention, and audit-export tasks fetch the current secret when opening database
  connections; frontend tasks have no database or AWS service permissions.
- API/worker task roles have only their required database, queue, and configured monitoring-role
  permissions. The audit-export task has a separate role limited to database-secret reads and S3
  writes to its archive prefix. Response automation remains disabled.
- SQS uses managed encryption, separate processing and delivery DLQs, partial-batch retry reporting,
  and visibility timeout of at least six times the worker timeout.
- CloudWatch receives Embedded Metric Format records from API requests and worker batches. Alarms
  cover API 5xx/latency, queue age/depth, both DLQs, worker failures, and database CPU/storage.
  `alarm_email` is optional; the SNS email subscription must be confirmed.
- A daily Fargate task exports incident and response-action audit records to a versioned, encrypted
  S3 bucket with Object Lock COMPLIANCE retention, then advances a database watermark only after
  S3 confirms the write. A second daily task removes expired raw CloudTrail events and their IDs
  from alert evidence references. Incident/response audit rows remain in PostgreSQL; their archive
  copies expire after the configured retention period. Retention and deletion must be reviewed
  against legal requirements before deployment.
- The task role can write only under the archive's `audit-trails/` prefix and cannot read or delete
  objects. The bucket blocks public access, denies non-TLS requests, and does not permit Terraform
  force-destroy. Daily task failures are sent to the optional operations email subscription.
- The stack does not create cross-account event-bus forwarding, source-account CloudTrail trails,
  VPC endpoints, WAF rules, or a full backup/restore program. Configure and test those separately
  before production acceptance.
- The API and frontend run in two AZs with CPU autoscaling and deployment rollback. This does not
  constitute a tested SLO, DR plan, or security certification.

Before teardown, preserve and inspect DLQ messages, create/verify database backups, and deliberately
disable ALB/RDS deletion protection through a reviewed change. Terraform destroy can delete data and
interrupt monitoring.
