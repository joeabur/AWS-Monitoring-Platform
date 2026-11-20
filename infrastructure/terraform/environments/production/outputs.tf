output "application_url" {
  description = "HTTPS application URL."
  value       = "https://${var.app_domain_name}"
}

output "load_balancer_dns_name" {
  description = "Application Load Balancer DNS hostname."
  value       = aws_lb.platform.dns_name
}

output "cognito_user_pool_id" {
  description = "Cognito user pool ID; create users administratively and provision their app roles."
  value       = aws_cognito_user_pool.platform.id
}

output "cognito_user_pool_client_id" {
  description = "Public OIDC client ID for the frontend."
  value       = aws_cognito_user_pool_client.web.id
}

output "cognito_issuer" {
  description = "Cognito issuer used by API JWT verification."
  value       = local.cognito_issuer
}

output "database_endpoint" {
  description = "Private RDS PostgreSQL endpoint."
  value       = aws_db_instance.platform.address
}

output "database_password_secret_arn" {
  description = "RDS-managed master credential secret ARN; grant access only to application task roles."
  value       = aws_db_instance.platform.master_user_secret[0].secret_arn
}

output "api_task_definition_arn" {
  description = "API task definition ARN; use it for the one-time reviewed Alembic migration task."
  value       = aws_ecs_task_definition.api.arn
}

output "retention_task_definition_arn" {
  description = "Scheduled retention Fargate task definition ARN."
  value       = aws_ecs_task_definition.retention.arn
}

output "audit_export_task_definition_arn" {
  description = "Scheduled immutable audit export Fargate task definition ARN."
  value       = aws_ecs_task_definition.audit_export.arn
}

output "audit_archive_bucket" {
  description = "S3 Object Lock bucket containing encrypted application audit exports."
  value       = aws_s3_bucket.audit_archive.bucket
}

output "events_queue_arn" {
  description = "SQS event queue ARN consumed by the Lambda worker."
  value       = module.event_pipeline.events_queue_arn
}

output "processing_dlq_arn" {
  description = "Worker processing dead-letter queue ARN."
  value       = module.event_pipeline.processing_dlq_arn
}

output "delivery_dlq_arn" {
  description = "EventBridge delivery dead-letter queue ARN."
  value       = module.event_pipeline.delivery_dlq_arn
}
