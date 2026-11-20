output "events_queue_arn" {
  description = "SQS queue ARN for the worker event-source mapping."
  value       = aws_sqs_queue.events.arn
}

output "events_queue_url" {
  description = "SQS queue URL consumed by the event worker."
  value       = aws_sqs_queue.events.url
}

output "events_queue_name" {
  description = "SQS queue name used by CloudWatch metrics and the worker."
  value       = aws_sqs_queue.events.name
}

output "processing_dlq_arn" {
  description = "DLQ receiving events the worker could not process after retries."
  value       = aws_sqs_queue.processing_dlq.arn
}

output "processing_dlq_url" {
  description = "SQS processing DLQ URL."
  value       = aws_sqs_queue.processing_dlq.url
}

output "processing_dlq_name" {
  description = "SQS processing DLQ name."
  value       = aws_sqs_queue.processing_dlq.name
}

output "delivery_dlq_arn" {
  description = "DLQ receiving events EventBridge could not deliver to SQS."
  value       = aws_sqs_queue.delivery_dlq.arn
}

output "delivery_dlq_url" {
  description = "SQS EventBridge delivery DLQ URL."
  value       = aws_sqs_queue.delivery_dlq.url
}

output "delivery_dlq_name" {
  description = "SQS EventBridge delivery DLQ name."
  value       = aws_sqs_queue.delivery_dlq.name
}

output "event_rule_arn" {
  description = "EventBridge rule ARN for monitoring and alarms."
  value       = aws_cloudwatch_event_rule.cloudtrail_management.arn
}

output "service_finding_rule_arns" {
  description = "EventBridge rule ARNs for GuardDuty, Security Hub, and AWS Config findings."
  value       = { for name, rule in aws_cloudwatch_event_rule.service_findings : name => rule.arn }
}
