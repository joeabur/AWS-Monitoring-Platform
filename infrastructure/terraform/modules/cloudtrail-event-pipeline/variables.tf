variable "name_prefix" {
  description = "Short prefix used for the EventBridge rule and SQS queues."
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z0-9_-]{1,40}$", var.name_prefix))
    error_message = "name_prefix must be 1-40 alphanumeric, dash, or underscore characters."
  }
}

variable "monitored_account_ids" {
  description = "AWS account IDs whose CloudTrail management events this regional rule accepts."
  type        = list(string)

  validation {
    condition = (
      length(var.monitored_account_ids) > 0 &&
      alltrue([for id in var.monitored_account_ids : can(regex("^[0-9]{12}$", id))])
    )
    error_message = "Provide at least one valid 12-digit AWS account ID."
  }
}

variable "event_bus_name" {
  description = "Optional EventBridge event bus name; null selects the default bus."
  type        = string
  default     = null
}

variable "message_retention_seconds" {
  description = "Retention for queued CloudTrail messages, from 60 seconds to 14 days."
  type        = number
  default     = 345600

  validation {
    condition = (
      var.message_retention_seconds >= 60 &&
      var.message_retention_seconds <= 1209600 &&
      floor(var.message_retention_seconds) == var.message_retention_seconds
    )
    error_message = "message_retention_seconds must be between 60 and 1209600."
  }
}

variable "max_receive_count" {
  description = "Receive attempts before SQS moves a poison message to its processing DLQ."
  type        = number
  default     = 5

  validation {
    condition = (
      var.max_receive_count >= 1 &&
      var.max_receive_count <= 1000 &&
      floor(var.max_receive_count) == var.max_receive_count
    )
    error_message = "max_receive_count must be between 1 and 1000."
  }

}

variable "worker_timeout_seconds" {
  description = "Worker timeout used to calculate a safe SQS message visibility timeout."
  type        = number
  default     = 30

  validation {
    condition     = var.worker_timeout_seconds >= 1 && var.worker_timeout_seconds <= 900
    error_message = "worker_timeout_seconds must be between 1 and 900."
  }
}

variable "batching_window_seconds" {
  description = "Maximum Lambda SQS batching window in seconds."
  type        = number
  default     = 0

  validation {
    condition     = var.batching_window_seconds >= 0 && var.batching_window_seconds <= 300
    error_message = "batching_window_seconds must be between 0 and 300."
  }
}
