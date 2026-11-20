resource "aws_sqs_queue" "processing_dlq" {
  name                      = "${var.name_prefix}-cloudtrail-dlq"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
}

resource "aws_sqs_queue" "events" {
  name                      = "${var.name_prefix}-cloudtrail-events"
  message_retention_seconds = var.message_retention_seconds
  visibility_timeout_seconds = max(
    180,
    6 * var.worker_timeout_seconds + var.batching_window_seconds
  )
  sqs_managed_sse_enabled = true
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.processing_dlq.arn
    maxReceiveCount     = var.max_receive_count
  })
}

resource "aws_sqs_queue" "delivery_dlq" {
  name                      = "${var.name_prefix}-eventbridge-delivery-dlq"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
}

resource "aws_cloudwatch_event_rule" "cloudtrail_management" {
  name           = "${var.name_prefix}-cloudtrail-management"
  event_bus_name = var.event_bus_name
  description    = "Route selected-account CloudTrail management events to the monitoring queue."
  event_pattern = jsonencode({
    account       = var.monitored_account_ids
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventCategory = ["Management"]
    }
  })
}

resource "aws_cloudwatch_event_rule" "service_findings" {
  for_each = {
    guardduty = {
      source      = "aws.guardduty"
      detail_type = "GuardDuty Finding"
    }
    securityhub = {
      source      = "aws.securityhub"
      detail_type = "Security Hub Findings - Imported"
    }
    config = {
      source      = "aws.config"
      detail_type = "Config Rules Compliance Change"
    }
  }

  name           = "${var.name_prefix}-${each.key}-findings"
  event_bus_name = var.event_bus_name
  description    = "Route selected-account ${each.key} findings to the monitoring queue."
  event_pattern = jsonencode({
    account       = var.monitored_account_ids
    source        = [each.value.source]
    "detail-type" = [each.value.detail_type]
  })
}

data "aws_iam_policy_document" "events_queue" {
  statement {
    sid       = "AllowMatchingEventBridgeRule"
    effect    = "Allow"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.events.arn]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values = concat(
        [aws_cloudwatch_event_rule.cloudtrail_management.arn],
        [for rule in aws_cloudwatch_event_rule.service_findings : rule.arn]
      )
    }
  }
}

data "aws_iam_policy_document" "delivery_dlq" {
  statement {
    sid       = "AllowEventBridgeDeliveryFailures"
    effect    = "Allow"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.delivery_dlq.arn]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values = concat(
        [aws_cloudwatch_event_rule.cloudtrail_management.arn],
        [for rule in aws_cloudwatch_event_rule.service_findings : rule.arn]
      )
    }
  }
}

resource "aws_sqs_queue_policy" "events" {
  queue_url = aws_sqs_queue.events.id
  policy    = data.aws_iam_policy_document.events_queue.json
}

resource "aws_sqs_queue_policy" "delivery_dlq" {
  queue_url = aws_sqs_queue.delivery_dlq.id
  policy    = data.aws_iam_policy_document.delivery_dlq.json
}

resource "aws_cloudwatch_event_target" "events_queue" {
  rule           = aws_cloudwatch_event_rule.cloudtrail_management.name
  event_bus_name = var.event_bus_name
  target_id      = "cloudtrail-sqs"
  arn            = aws_sqs_queue.events.arn
  depends_on     = [aws_sqs_queue_policy.events, aws_sqs_queue_policy.delivery_dlq]

  dead_letter_config {
    arn = aws_sqs_queue.delivery_dlq.arn
  }

  retry_policy {
    maximum_event_age_in_seconds = 86400
    maximum_retry_attempts       = 185
  }
}

resource "aws_cloudwatch_event_target" "service_findings" {
  for_each = aws_cloudwatch_event_rule.service_findings

  rule           = each.value.name
  event_bus_name = var.event_bus_name
  target_id      = "${each.key}-sqs"
  arn            = aws_sqs_queue.events.arn
  depends_on     = [aws_sqs_queue_policy.events, aws_sqs_queue_policy.delivery_dlq]

  dead_letter_config {
    arn = aws_sqs_queue.delivery_dlq.arn
  }

  retry_policy {
    maximum_event_age_in_seconds = 86400
    maximum_retry_attempts       = 185
  }
}
