output "events_queue_arn" {
  description = "SQS queue ARN for the worker event-source mapping."
  value       = aws_sqs_queue.events.arn
}

output "events_queue_url" {
  description = "SQS queue URL consumed by the event worker."
  value       = aws_sqs_queue.events.url
}

output "processing_dlq_arn" {
  description = "DLQ receiving events the worker could not process after retries."
  value       = aws_sqs_queue.processing_dlq.arn
}

output "delivery_dlq_arn" {
  description = "DLQ receiving events EventBridge could not deliver to SQS."
  value       = aws_sqs_queue.delivery_dlq.arn
}

output "event_rule_arn" {
  description = "EventBridge rule ARN for monitoring and alarms."
  value       = aws_cloudwatch_event_rule.cloudtrail_management.arn
}
