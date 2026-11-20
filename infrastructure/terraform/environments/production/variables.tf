variable "aws_region" {
  description = "AWS Region for the production stack."
  type        = string
}

variable "name_prefix" {
  description = "Lowercase, globally unique-safe prefix for named resources."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,18}[a-z0-9]$", var.name_prefix))
    error_message = "name_prefix must be 3-20 lowercase letters, digits, or dashes, and start with a letter."
  }
}

variable "app_domain_name" {
  description = "Public HTTPS hostname served by the Application Load Balancer."
  type        = string
}

variable "alb_certificate_arn" {
  description = "ACM certificate ARN in aws_region, valid for app_domain_name."
  type        = string
}

variable "route53_zone_id" {
  description = "Optional Route 53 hosted zone ID for an ALB alias record."
  type        = string
  default     = null
}

variable "cognito_domain_prefix" {
  description = "Globally unique Cognito hosted-domain prefix."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$", var.cognito_domain_prefix))
    error_message = "cognito_domain_prefix must contain 2-63 lowercase letters, digits, or dashes."
  }
}

variable "api_image_uri" {
  description = "Immutable API container image URI, preferably pinned by digest."
  type        = string
}

variable "frontend_image_uri" {
  description = "Immutable frontend container image URI, preferably pinned by digest."
  type        = string
}

variable "worker_image_uri" {
  description = "Immutable Lambda-compatible worker image URI, preferably pinned by digest."
  type        = string
}

variable "monitored_accounts" {
  description = "Accounts and optional read-only role ARNs exposed to application collectors."
  type = list(object({
    account_id = string
    name       = string
    role_arn   = optional(string)
  }))

  validation {
    condition = (
      length(var.monitored_accounts) > 0 &&
      alltrue([
        for account in var.monitored_accounts :
        can(regex("^[0-9]{12}$", account.account_id)) &&
        length(trimspace(account.name)) > 0 &&
        (
          account.role_arn == null ||
          can(regex("^arn:aws:iam::${account.account_id}:role/.+$", account.role_arn))
        )
      ]) &&
      length(distinct([for account in var.monitored_accounts : account.account_id])) ==
      length(var.monitored_accounts)
    )
    error_message = "Provide unique 12-digit account IDs, names, and optional IAM role ARNs in those accounts."
  }
}

variable "vpc_cidr" {
  description = "IPv4 CIDR for the dedicated production VPC; at least a /20 is required."
  type        = string
  default     = "10.80.0.0/16"

  validation {
    condition     = can(cidrnetmask(var.vpc_cidr)) && tonumber(split("/", var.vpc_cidr)[1]) <= 20
    error_message = "vpc_cidr must be a valid IPv4 network with a /20 or larger address space."
  }
}

variable "db_instance_class" {
  description = "RDS PostgreSQL instance class."
  type        = string
  default     = "db.t4g.medium"
}

variable "db_name" {
  description = "PostgreSQL database name."
  type        = string
  default     = "monitoring"
}

variable "db_username" {
  description = "RDS master username; its generated password is managed by RDS in Secrets Manager."
  type        = string
  default     = "monitor_admin"
}

variable "db_engine_version" {
  description = "Supported PostgreSQL engine version in aws_region."
  type        = string
  default     = "16.4"
}

variable "db_allocated_storage_gb" {
  description = "Initial encrypted RDS storage allocation."
  type        = number
  default     = 100

  validation {
    condition     = var.db_allocated_storage_gb >= 20 && var.db_allocated_storage_gb <= 65536
    error_message = "db_allocated_storage_gb must be between 20 and 65536."
  }
}

variable "db_max_allocated_storage_gb" {
  description = "RDS autoscaling storage limit."
  type        = number
  default     = 500

  validation {
    condition     = var.db_max_allocated_storage_gb >= var.db_allocated_storage_gb
    error_message = "db_max_allocated_storage_gb must be at least db_allocated_storage_gb."
  }
}

variable "api_desired_count" {
  description = "Desired API task count; at least two for production availability."
  type        = number
  default     = 2

  validation {
    condition = (
      var.api_desired_count >= 2 &&
      floor(var.api_desired_count) == var.api_desired_count &&
      var.api_max_count >= var.api_desired_count
    )
    error_message = "api_desired_count must be an integer of at least two."
  }
}

variable "frontend_desired_count" {
  description = "Desired frontend task count; at least two for production availability."
  type        = number
  default     = 2

  validation {
    condition = (
      var.frontend_desired_count >= 2 &&
      floor(var.frontend_desired_count) == var.frontend_desired_count &&
      var.frontend_max_count >= var.frontend_desired_count
    )
    error_message = "frontend_desired_count must be an integer of at least two."
  }
}

variable "api_max_count" {
  description = "Maximum API task count for CPU-based autoscaling."
  type        = number
  default     = 6
}

variable "frontend_max_count" {
  description = "Maximum frontend task count for CPU-based autoscaling."
  type        = number
  default     = 6
}

variable "worker_timeout_seconds" {
  description = "Worker Lambda timeout; queue visibility is configured to at least six times this value."
  type        = number
  default     = 30

  validation {
    condition     = var.worker_timeout_seconds >= 1 && var.worker_timeout_seconds <= 900
    error_message = "worker_timeout_seconds must be between 1 and 900."
  }
}

variable "evidence_retention_days" {
  description = "Retention period for raw event evidence and compliance-locked audit archive objects."
  type        = number
  default     = 90

  validation {
    condition = (
      var.evidence_retention_days >= 1 &&
      var.evidence_retention_days <= 36500 &&
      floor(var.evidence_retention_days) == var.evidence_retention_days
    )
    error_message = "evidence_retention_days must be a whole number between 1 and 36500."
  }
}

variable "alarm_email" {
  description = "Optional email subscription for CloudWatch alarm notifications."
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags applied to supported AWS resources."
  type        = map(string)
  default = {
    Application = "AWSMonitoringPlatform"
    Environment = "production"
    ManagedBy   = "Terraform"
  }
}
