# CloudTrail EventBridge and SQS module

This opt-in regional module routes CloudTrail management events and GuardDuty, Security Hub, and
AWS Config findings for an explicit list of AWS account IDs to an encrypted SQS queue. A processing
DLQ captures messages rejected by the worker after the configured receive count; a separate
delivery DLQ captures EventBridge target delivery failures. Rules are scoped by account and source.
CloudTrail data events are not selected by this module.

The queue is intended for a worker image built from `backend/Dockerfile.worker`, whose handler is
`app.ingestion.worker.lambda_handler`. Configure the Lambda SQS event-source mapping with
`ReportBatchItemFailures` so a bad message does not force successful messages in the same batch to
be replayed. With the queue's current 180-second visibility timeout and no batching window, keep the
Lambda timeout at or below 30 seconds; otherwise increase queue visibility to at least six times the
function timeout plus the batching window. Inject `DATABASE_URL` from a secret manager and provide
network access to PostgreSQL. The worker does not need `JWT_SECRET_KEY`. Grant the worker only
`sqs:ReceiveMessage`, `sqs:DeleteMessage`, and
`sqs:GetQueueAttributes` on `events_queue_arn`; the Terraform module does not create that consumer
role or deploy a Lambda.

No root module calls this module automatically. The caller must use an appropriately scoped AWS
provider in the target region and pass account IDs intentionally. Review EventBridge event coverage and service-specific event shapes before deployment. CloudTrail,
GuardDuty, Security Hub, and AWS Config must be enabled and configured in the source account/region.
This module matches events already available on its configured event bus; cross-account event-bus
forwarding and permissions must be configured separately when monitoring other accounts.

SQS and EventBridge are metered services. Cost depends on event volume, retries, retention and
regional traffic; this module is not applied in local development. Estimate costs and set budgets
before deployment, and remove the calling stack to destroy these resources. DLQ messages must be
reviewed or safely replayed before deletion.
