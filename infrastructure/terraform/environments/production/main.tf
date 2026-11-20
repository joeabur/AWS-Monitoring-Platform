data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  availability_zones = slice(data.aws_availability_zones.available.names, 0, 2)
  monitored_role_arns = [
    for account in var.monitored_accounts : account.role_arn
    if account.role_arn != null
  ]
  monitored_accounts_json = jsonencode([
    for account in var.monitored_accounts : {
      account_id = account.account_id
      name       = account.name
      role_arn   = account.role_arn
    }
  ])
  cognito_issuer    = "https://cognito-idp.${var.aws_region}.amazonaws.com/${aws_cognito_user_pool.platform.id}"
  api_log_group     = "/ecs/${var.name_prefix}/api"
  web_log_group     = "/ecs/${var.name_prefix}/frontend"
  worker_log_group  = "/aws/lambda/${var.name_prefix}-event-worker"
  audit_bucket_name = "${var.name_prefix}-${data.aws_caller_identity.current.account_id}-${var.aws_region}-audit"
}

resource "aws_vpc" "platform" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags                 = { Name = "${var.name_prefix}-vpc" }
}

resource "aws_internet_gateway" "platform" {
  vpc_id = aws_vpc.platform.id
  tags   = { Name = "${var.name_prefix}-igw" }
}

resource "aws_subnet" "public" {
  count                   = length(local.availability_zones)
  vpc_id                  = aws_vpc.platform.id
  availability_zone       = local.availability_zones[count.index]
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index)
  map_public_ip_on_launch = true
  tags                    = { Name = "${var.name_prefix}-public-${count.index + 1}" }
}

resource "aws_subnet" "application" {
  count                   = length(local.availability_zones)
  vpc_id                  = aws_vpc.platform.id
  availability_zone       = local.availability_zones[count.index]
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index + 16)
  map_public_ip_on_launch = false
  tags                    = { Name = "${var.name_prefix}-application-${count.index + 1}" }
}

resource "aws_subnet" "database" {
  count                   = length(local.availability_zones)
  vpc_id                  = aws_vpc.platform.id
  availability_zone       = local.availability_zones[count.index]
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index + 32)
  map_public_ip_on_launch = false
  tags                    = { Name = "${var.name_prefix}-database-${count.index + 1}" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.platform.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.platform.id
  }
  tags = { Name = "${var.name_prefix}-public" }
}

resource "aws_route_table_association" "public" {
  count          = length(local.availability_zones)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_eip" "nat" {
  count  = length(local.availability_zones)
  domain = "vpc"
  tags   = { Name = "${var.name_prefix}-nat-${count.index + 1}" }
}

resource "aws_nat_gateway" "platform" {
  count         = length(local.availability_zones)
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id
  depends_on    = [aws_internet_gateway.platform]
  tags          = { Name = "${var.name_prefix}-nat-${count.index + 1}" }
}

resource "aws_route_table" "application" {
  count  = length(local.availability_zones)
  vpc_id = aws_vpc.platform.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.platform[count.index].id
  }
  tags = { Name = "${var.name_prefix}-application-${count.index + 1}" }
}

resource "aws_route_table_association" "application" {
  count          = length(local.availability_zones)
  subnet_id      = aws_subnet.application[count.index].id
  route_table_id = aws_route_table.application[count.index].id
}

resource "aws_route_table" "database" {
  count  = length(local.availability_zones)
  vpc_id = aws_vpc.platform.id
  tags   = { Name = "${var.name_prefix}-database-${count.index + 1}" }
}

resource "aws_route_table_association" "database" {
  count          = length(local.availability_zones)
  subnet_id      = aws_subnet.database[count.index].id
  route_table_id = aws_route_table.database[count.index].id
}

resource "aws_security_group" "load_balancer" {
  name        = "${var.name_prefix}-alb"
  description = "Public HTTPS ingress only."
  vpc_id      = aws_vpc.platform.id
  ingress {
    description = "HTTP redirect to HTTPS"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "HTTPS application ingress"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "${var.name_prefix}-alb" }
}

resource "aws_security_group" "application" {
  name        = "${var.name_prefix}-application"
  description = "Application tasks accept traffic only from the load balancer."
  vpc_id      = aws_vpc.platform.id
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "${var.name_prefix}-application" }
}

resource "aws_security_group" "frontend" {
  name        = "${var.name_prefix}-frontend"
  description = "Frontend tasks accept traffic only from the load balancer."
  vpc_id      = aws_vpc.platform.id
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "${var.name_prefix}-frontend" }
}

resource "aws_vpc_security_group_ingress_rule" "api_from_alb" {
  security_group_id            = aws_security_group.application.id
  referenced_security_group_id = aws_security_group.load_balancer.id
  ip_protocol                  = "tcp"
  from_port                    = 8000
  to_port                      = 8000
  description                  = "API traffic from ALB."
}

resource "aws_vpc_security_group_ingress_rule" "frontend_from_alb" {
  security_group_id            = aws_security_group.frontend.id
  referenced_security_group_id = aws_security_group.load_balancer.id
  ip_protocol                  = "tcp"
  from_port                    = 3000
  to_port                      = 3000
  description                  = "Frontend traffic from ALB."
}

resource "aws_security_group" "worker" {
  name        = "${var.name_prefix}-worker"
  description = "Isolated Lambda worker egress to PostgreSQL and AWS APIs."
  vpc_id      = aws_vpc.platform.id
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "${var.name_prefix}-worker" }
}

resource "aws_security_group" "database" {
  name        = "${var.name_prefix}-database"
  description = "PostgreSQL ingress from application and event worker only."
  vpc_id      = aws_vpc.platform.id
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = { Name = "${var.name_prefix}-database" }
}

resource "aws_vpc_security_group_ingress_rule" "database_from_application" {
  security_group_id            = aws_security_group.database.id
  referenced_security_group_id = aws_security_group.application.id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
}

resource "aws_vpc_security_group_ingress_rule" "database_from_worker" {
  security_group_id            = aws_security_group.database.id
  referenced_security_group_id = aws_security_group.worker.id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
}

resource "aws_db_subnet_group" "platform" {
  name       = "${var.name_prefix}-db"
  subnet_ids = aws_subnet.database[*].id
  tags       = { Name = "${var.name_prefix}-db" }
}

resource "aws_db_instance" "platform" {
  identifier                      = "${var.name_prefix}-postgres"
  engine                          = "postgres"
  engine_version                  = var.db_engine_version
  instance_class                  = var.db_instance_class
  db_name                         = var.db_name
  username                        = var.db_username
  manage_master_user_password     = true
  port                            = 5432
  allocated_storage               = var.db_allocated_storage_gb
  max_allocated_storage           = var.db_max_allocated_storage_gb
  storage_type                    = "gp3"
  storage_encrypted               = true
  multi_az                        = true
  publicly_accessible             = false
  db_subnet_group_name            = aws_db_subnet_group.platform.name
  vpc_security_group_ids          = [aws_security_group.database.id]
  backup_retention_period         = 14
  backup_window                   = "03:00-04:00"
  maintenance_window              = "sun:04:00-sun:05:00"
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  auto_minor_version_upgrade      = true
  deletion_protection             = true
  skip_final_snapshot             = false
  final_snapshot_identifier       = "${var.name_prefix}-final-snapshot"
  apply_immediately               = false
  copy_tags_to_snapshot           = true
  tags                            = { Name = "${var.name_prefix}-postgres" }
}

resource "aws_s3_bucket" "audit_archive" {
  bucket              = local.audit_bucket_name
  object_lock_enabled = true
  force_destroy       = false
  tags                = { Name = local.audit_bucket_name }
}

resource "aws_s3_bucket_public_access_block" "audit_archive" {
  bucket                  = aws_s3_bucket.audit_archive.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "audit_archive" {
  bucket = aws_s3_bucket.audit_archive.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_archive" {
  bucket = aws_s3_bucket.audit_archive.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_object_lock_configuration" "audit_archive" {
  bucket = aws_s3_bucket.audit_archive.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.evidence_retention_days
    }
  }
  depends_on = [aws_s3_bucket_versioning.audit_archive]
}

resource "aws_s3_bucket_lifecycle_configuration" "audit_archive" {
  bucket = aws_s3_bucket.audit_archive.id
  rule {
    id     = "expire-locked-audit-exports"
    status = "Enabled"
    filter {}
    expiration {
      days = var.evidence_retention_days + 1
    }
    noncurrent_version_expiration {
      noncurrent_days = var.evidence_retention_days + 1
    }
  }
  depends_on = [aws_s3_bucket_versioning.audit_archive]
}

data "aws_iam_policy_document" "audit_archive" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.audit_archive.arn, "${aws_s3_bucket.audit_archive.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "audit_archive" {
  bucket = aws_s3_bucket.audit_archive.id
  policy = data.aws_iam_policy_document.audit_archive.json
}

resource "aws_cognito_user_pool" "platform" {
  name                     = "${var.name_prefix}-users"
  mfa_configuration        = "ON"
  username_attributes      = ["email"]
  auto_verified_attributes = ["email"]
  deletion_protection      = "ACTIVE"

  software_token_mfa_configuration {
    enabled = true
  }

  admin_create_user_config {
    allow_admin_create_user_only = true
  }

  password_policy {
    minimum_length                   = 14
    require_lowercase                = true
    require_numbers                  = true
    require_symbols                  = true
    require_uppercase                = true
    temporary_password_validity_days = 7
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

  tags = { Name = "${var.name_prefix}-users" }
}

resource "aws_cognito_user_pool_domain" "platform" {
  domain       = var.cognito_domain_prefix
  user_pool_id = aws_cognito_user_pool.platform.id
}

resource "aws_cognito_user_pool_client" "web" {
  name                                 = "${var.name_prefix}-web"
  user_pool_id                         = aws_cognito_user_pool.platform.id
  generate_secret                      = false
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid", "email"]
  callback_urls                        = ["https://${var.app_domain_name}"]
  logout_urls                          = ["https://${var.app_domain_name}"]
  supported_identity_providers         = ["COGNITO"]
  explicit_auth_flows                  = ["ALLOW_REFRESH_TOKEN_AUTH"]
  prevent_user_existence_errors        = "ENABLED"
  access_token_validity                = 30
  id_token_validity                    = 30
  refresh_token_validity               = 7

  token_validity_units {
    access_token  = "minutes"
    id_token      = "minutes"
    refresh_token = "days"
  }
}

resource "aws_lb" "platform" {
  name                       = "${var.name_prefix}-alb"
  internal                   = false
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.load_balancer.id]
  subnets                    = aws_subnet.public[*].id
  enable_deletion_protection = true
  drop_invalid_header_fields = true
  tags                       = { Name = "${var.name_prefix}-alb" }
}

resource "aws_lb_target_group" "api" {
  name        = "${var.name_prefix}-api"
  port        = 8000
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = aws_vpc.platform.id

  health_check {
    enabled             = true
    path                = "/api/v1/health/ready"
    matcher             = "200"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_target_group" "frontend" {
  name        = "${var.name_prefix}-web"
  port        = 3000
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = aws_vpc.platform.id

  health_check {
    enabled             = true
    path                = "/"
    matcher             = "200-399"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.platform.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.platform.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.alb_certificate_arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.frontend.arn
  }
}

resource "aws_lb_listener_rule" "api" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 10
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
  condition {
    path_pattern {
      values = ["/api/*"]
    }
  }
}

resource "aws_route53_record" "app_ipv4" {
  count   = var.route53_zone_id == null ? 0 : 1
  zone_id = var.route53_zone_id
  name    = var.app_domain_name
  type    = "A"
  alias {
    name                   = aws_lb.platform.dns_name
    zone_id                = aws_lb.platform.zone_id
    evaluate_target_health = true
  }
}

resource "aws_route53_record" "app_ipv6" {
  count   = var.route53_zone_id == null ? 0 : 1
  zone_id = var.route53_zone_id
  name    = var.app_domain_name
  type    = "AAAA"
  alias {
    name                   = aws_lb.platform.dns_name
    zone_id                = aws_lb.platform.zone_id
    evaluate_target_health = true
  }
}

resource "aws_ecs_cluster" "platform" {
  name = "${var.name_prefix}-cluster"
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
  tags = { Name = "${var.name_prefix}-cluster" }
}

resource "aws_cloudwatch_log_group" "api" {
  name              = local.api_log_group
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "frontend" {
  name              = local.web_log_group
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "worker" {
  name              = local.worker_log_group
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "audit_export" {
  name              = "/ecs/${var.name_prefix}/audit-export"
  retention_in_days = 30
}

resource "aws_iam_role" "ecs_execution" {
  name = "${var.name_prefix}-ecs-execution"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_execution" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role" "application" {
  name = "${var.name_prefix}-application"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role" "frontend" {
  name = "${var.name_prefix}-frontend"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role" "retention" {
  name = "${var.name_prefix}-retention"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "retention" {
  name = "${var.name_prefix}-retention-secret"
  role = aws_iam_role.retention.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = aws_db_instance.platform.master_user_secret[0].secret_arn
    }]
  })
}

resource "aws_iam_role" "audit_export" {
  name = "${var.name_prefix}-audit-export"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "audit_export" {
  name = "${var.name_prefix}-audit-archive-write"
  role = aws_iam_role.audit_export.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = aws_db_instance.platform.master_user_secret[0].secret_arn
      },
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:PutObjectRetention"]
        Resource = "${aws_s3_bucket.audit_archive.arn}/audit-trails/*"
      }
    ]
  })
}

data "aws_iam_policy_document" "application" {
  statement {
    sid       = "ReadRdsManagedSecret"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_db_instance.platform.master_user_secret[0].secret_arn]
  }

  dynamic "statement" {
    for_each = length(local.monitored_role_arns) == 0 ? [] : [true]
    content {
      sid       = "AssumeConfiguredMonitoringRoles"
      actions   = ["sts:AssumeRole"]
      resources = local.monitored_role_arns
    }
  }
}

resource "aws_iam_role_policy" "application" {
  name   = "${var.name_prefix}-application"
  role   = aws_iam_role.application.id
  policy = data.aws_iam_policy_document.application.json
}

resource "aws_iam_role" "worker" {
  name = "${var.name_prefix}-worker"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "worker_basic" {
  role       = aws_iam_role.worker.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "worker_vpc" {
  role       = aws_iam_role.worker.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

resource "aws_iam_role_policy" "worker" {
  name = "${var.name_prefix}-worker"
  role = aws_iam_role.worker.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [
        {
          Effect   = "Allow"
          Action   = ["secretsmanager:GetSecretValue"]
          Resource = aws_db_instance.platform.master_user_secret[0].secret_arn
        },
        {
          Effect   = "Allow"
          Action   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
          Resource = module.event_pipeline.events_queue_arn
        }
      ],
      length(local.monitored_role_arns) == 0 ? [] : [
        {
          Effect   = "Allow"
          Action   = ["sts:AssumeRole"]
          Resource = local.monitored_role_arns
        }
      ]
    )
  })
}

resource "aws_ecs_task_definition" "api" {
  family                   = "${var.name_prefix}-api"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 1024
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.application.arn

  container_definitions = jsonencode([{
    name      = "api"
    image     = var.api_image_uri
    essential = true
    portMappings = [{
      containerPort = 8000
      hostPort      = 8000
      protocol      = "tcp"
    }]
    environment = [
      { name = "ENVIRONMENT", value = "production" },
      { name = "AUTH_PROVIDER", value = "cognito" },
      { name = "COGNITO_ISSUER", value = local.cognito_issuer },
      { name = "COGNITO_CLIENT_ID", value = aws_cognito_user_pool_client.web.id },
      { name = "CORS_ORIGINS", value = "https://${var.app_domain_name}" },
      { name = "DATABASE_HOST", value = aws_db_instance.platform.address },
      { name = "DATABASE_NAME", value = var.db_name },
      { name = "DATABASE_PORT", value = "5432" },
      { name = "DATABASE_PASSWORD_SECRET_ARN", value = aws_db_instance.platform.master_user_secret[0].secret_arn },
      { name = "DATABASE_SSLROOTCERT", value = "/etc/ssl/certs/ca-certificates.crt" },
      { name = "AUDIT_ARCHIVE_BUCKET", value = aws_s3_bucket.audit_archive.bucket },
      { name = "EVIDENCE_RETENTION_DAYS", value = tostring(var.evidence_retention_days) },
      { name = "MONITORED_AWS_ACCOUNTS", value = local.monitored_accounts_json },
      { name = "MIGRATIONS_ON_STARTUP", value = "false" },
      { name = "RESPONSE_ACTIONS_ENABLED", value = "false" },
      { name = "RESPONSE_DRY_RUN", value = "true" },
      { name = "MCP_ENABLED", value = "false" }
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = local.api_log_group
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = "api"
      }
    }
    healthCheck = {
      command     = ["CMD-SHELL", "python -c \"import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health/live')\""]
      interval    = 30
      timeout     = 5
      retries     = 3
      startPeriod = 30
    }
  }])
}

resource "aws_ecs_task_definition" "frontend" {
  family                   = "${var.name_prefix}-frontend"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.frontend.arn

  container_definitions = jsonencode([{
    name      = "frontend"
    image     = var.frontend_image_uri
    essential = true
    portMappings = [{
      containerPort = 3000
      hostPort      = 3000
      protocol      = "tcp"
    }]
    environment = [
      { name = "AUTH_PROVIDER", value = "cognito" },
      { name = "COGNITO_ISSUER", value = local.cognito_issuer },
      { name = "COGNITO_CLIENT_ID", value = aws_cognito_user_pool_client.web.id },
      { name = "COGNITO_DOMAIN", value = "https://${var.cognito_domain_prefix}.auth.${var.aws_region}.amazoncognito.com" },
      { name = "COGNITO_REDIRECT_URI", value = "https://${var.app_domain_name}" },
      { name = "COGNITO_POST_LOGOUT_REDIRECT_URI", value = "https://${var.app_domain_name}" },
      { name = "NEXT_PUBLIC_API_BASE_URL", value = "" }
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = local.web_log_group
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = "frontend"
      }
    }
  }])
}

resource "aws_ecs_service" "api" {
  name                               = "${var.name_prefix}-api"
  cluster                            = aws_ecs_cluster.platform.id
  task_definition                    = aws_ecs_task_definition.api.arn
  desired_count                      = var.api_desired_count
  launch_type                        = "FARGATE"
  platform_version                   = "1.4.0"
  health_check_grace_period_seconds  = 60
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = aws_subnet.application[*].id
    security_groups  = [aws_security_group.application.id]
    assign_public_ip = false
  }
  load_balancer {
    target_group_arn = aws_lb_target_group.api.arn
    container_name   = "api"
    container_port   = 8000
  }
  depends_on = [aws_lb_listener_rule.api, aws_iam_role_policy.application]
}

resource "aws_ecs_service" "frontend" {
  name                               = "${var.name_prefix}-frontend"
  cluster                            = aws_ecs_cluster.platform.id
  task_definition                    = aws_ecs_task_definition.frontend.arn
  desired_count                      = var.frontend_desired_count
  launch_type                        = "FARGATE"
  platform_version                   = "1.4.0"
  health_check_grace_period_seconds  = 60
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = aws_subnet.application[*].id
    security_groups  = [aws_security_group.frontend.id]
    assign_public_ip = false
  }
  load_balancer {
    target_group_arn = aws_lb_target_group.frontend.arn
    container_name   = "frontend"
    container_port   = 3000
  }
}

resource "aws_appautoscaling_target" "api" {
  max_capacity       = var.api_max_count
  min_capacity       = var.api_desired_count
  resource_id        = "service/${aws_ecs_cluster.platform.name}/${aws_ecs_service.api.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "api_cpu" {
  name               = "${var.name_prefix}-api-cpu"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.api.resource_id
  scalable_dimension = aws_appautoscaling_target.api.scalable_dimension
  service_namespace  = aws_appautoscaling_target.api.service_namespace
  target_tracking_scaling_policy_configuration {
    target_value       = 65
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
  }
}

resource "aws_appautoscaling_target" "frontend" {
  max_capacity       = var.frontend_max_count
  min_capacity       = var.frontend_desired_count
  resource_id        = "service/${aws_ecs_cluster.platform.name}/${aws_ecs_service.frontend.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "frontend_cpu" {
  name               = "${var.name_prefix}-frontend-cpu"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.frontend.resource_id
  scalable_dimension = aws_appautoscaling_target.frontend.scalable_dimension
  service_namespace  = aws_appautoscaling_target.frontend.service_namespace
  target_tracking_scaling_policy_configuration {
    target_value       = 65
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
  }
}

module "event_pipeline" {
  source = "../../modules/cloudtrail-event-pipeline"

  name_prefix            = var.name_prefix
  monitored_account_ids  = [for account in var.monitored_accounts : account.account_id]
  worker_timeout_seconds = var.worker_timeout_seconds
}

resource "aws_lambda_function" "event_worker" {
  function_name = "${var.name_prefix}-event-worker"
  role          = aws_iam_role.worker.arn
  package_type  = "Image"
  image_uri     = var.worker_image_uri
  timeout       = var.worker_timeout_seconds
  memory_size   = 512
  architectures = ["x86_64"]

  vpc_config {
    subnet_ids         = aws_subnet.application[*].id
    security_group_ids = [aws_security_group.worker.id]
  }

  environment {
    variables = {
      ENVIRONMENT                  = "production"
      AUTH_PROVIDER                = "cognito"
      COGNITO_ISSUER               = local.cognito_issuer
      COGNITO_CLIENT_ID            = aws_cognito_user_pool_client.web.id
      CORS_ORIGINS                 = "https://${var.app_domain_name}"
      DATABASE_HOST                = aws_db_instance.platform.address
      DATABASE_NAME                = var.db_name
      DATABASE_PORT                = "5432"
      DATABASE_PASSWORD_SECRET_ARN = aws_db_instance.platform.master_user_secret[0].secret_arn
      DATABASE_SSLROOTCERT         = "/etc/ssl/certs/ca-certificates.crt"
      AUDIT_ARCHIVE_BUCKET         = aws_s3_bucket.audit_archive.bucket
      EVIDENCE_RETENTION_DAYS      = tostring(var.evidence_retention_days)
      MONITORED_AWS_ACCOUNTS       = local.monitored_accounts_json
      RESPONSE_ACTIONS_ENABLED     = "false"
      RESPONSE_DRY_RUN             = "true"
      MCP_ENABLED                  = "false"
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.worker_basic,
    aws_iam_role_policy_attachment.worker_vpc,
    aws_iam_role_policy.worker,
    aws_cloudwatch_log_group.worker
  ]
}

resource "aws_lambda_event_source_mapping" "events" {
  event_source_arn                   = module.event_pipeline.events_queue_arn
  function_name                      = aws_lambda_function.event_worker.arn
  batch_size                         = 10
  maximum_batching_window_in_seconds = 0
  function_response_types            = ["ReportBatchItemFailures"]
  scaling_config {
    maximum_concurrency = 10
  }
}

resource "aws_ecs_task_definition" "retention" {
  family                   = "${var.name_prefix}-retention"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.retention.arn

  container_definitions = jsonencode([{
    name      = "retention"
    image     = var.api_image_uri
    essential = true
    command   = ["python", "-m", "app.scripts.prune_events", "--older-than-days", tostring(var.evidence_retention_days), "--apply"]
    environment = [
      { name = "ENVIRONMENT", value = "production" },
      { name = "AUTH_PROVIDER", value = "cognito" },
      { name = "COGNITO_ISSUER", value = local.cognito_issuer },
      { name = "COGNITO_CLIENT_ID", value = aws_cognito_user_pool_client.web.id },
      { name = "CORS_ORIGINS", value = "https://${var.app_domain_name}" },
      { name = "DATABASE_HOST", value = aws_db_instance.platform.address },
      { name = "DATABASE_NAME", value = var.db_name },
      { name = "DATABASE_PORT", value = "5432" },
      { name = "DATABASE_PASSWORD_SECRET_ARN", value = aws_db_instance.platform.master_user_secret[0].secret_arn },
      { name = "DATABASE_SSLROOTCERT", value = "/etc/ssl/certs/ca-certificates.crt" },
      { name = "AUDIT_ARCHIVE_BUCKET", value = aws_s3_bucket.audit_archive.bucket },
      { name = "EVIDENCE_RETENTION_DAYS", value = tostring(var.evidence_retention_days) },
      { name = "MIGRATIONS_ON_STARTUP", value = "false" }
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = local.api_log_group
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = "retention"
      }
    }
  }])
}

resource "aws_ecs_task_definition" "audit_export" {
  family                   = "${var.name_prefix}-audit-export"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.audit_export.arn

  container_definitions = jsonencode([{
    name      = "audit-export"
    image     = var.api_image_uri
    essential = true
    command   = ["python", "-m", "app.scripts.export_audit"]
    environment = [
      { name = "ENVIRONMENT", value = "production" },
      { name = "AUTH_PROVIDER", value = "cognito" },
      { name = "COGNITO_ISSUER", value = local.cognito_issuer },
      { name = "COGNITO_CLIENT_ID", value = aws_cognito_user_pool_client.web.id },
      { name = "CORS_ORIGINS", value = "https://${var.app_domain_name}" },
      { name = "DATABASE_HOST", value = aws_db_instance.platform.address },
      { name = "DATABASE_NAME", value = var.db_name },
      { name = "DATABASE_PORT", value = "5432" },
      { name = "DATABASE_PASSWORD_SECRET_ARN", value = aws_db_instance.platform.master_user_secret[0].secret_arn },
      { name = "DATABASE_SSLROOTCERT", value = "/etc/ssl/certs/ca-certificates.crt" },
      { name = "AUDIT_ARCHIVE_BUCKET", value = aws_s3_bucket.audit_archive.bucket },
      { name = "EVIDENCE_RETENTION_DAYS", value = tostring(var.evidence_retention_days) }
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = "/ecs/${var.name_prefix}/audit-export"
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = "audit-export"
      }
    }
  }])
}

resource "aws_iam_role" "retention_scheduler" {
  name = "${var.name_prefix}-retention-scheduler"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "scheduler.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "retention_scheduler" {
  name = "${var.name_prefix}-run-retention"
  role = aws_iam_role.retention_scheduler.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["ecs:RunTask"]
        Resource = aws_ecs_task_definition.retention.arn
        Condition = {
          ArnEquals = { "ecs:cluster" = aws_ecs_cluster.platform.arn }
        }
      },
      {
        Effect   = "Allow"
        Action   = ["iam:PassRole"]
        Resource = [aws_iam_role.ecs_execution.arn, aws_iam_role.retention.arn]
        Condition = {
          StringEquals = { "iam:PassedToService" = "ecs-tasks.amazonaws.com" }
        }
      }
    ]
  })
}

resource "aws_scheduler_schedule" "retention" {
  name                         = "${var.name_prefix}-event-retention"
  description                  = "Run the configured CloudTrail event retention policy daily."
  schedule_expression          = "cron(0 3 * * ? *)"
  schedule_expression_timezone = "UTC"
  state                        = "ENABLED"

  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = aws_ecs_cluster.platform.arn
    role_arn = aws_iam_role.retention_scheduler.arn
    input = jsonencode({
      containerOverrides = [{
        name    = "retention"
        command = ["python", "-m", "app.scripts.prune_events", "--older-than-days", tostring(var.evidence_retention_days), "--apply"]
      }]
    })
    ecs_parameters {
      task_definition_arn = aws_ecs_task_definition.retention.arn
      task_count          = 1
      launch_type         = "FARGATE"
      platform_version    = "1.4.0"
      network_configuration {
        assign_public_ip = false
        subnets          = aws_subnet.application[*].id
        security_groups  = [aws_security_group.application.id]
      }
    }
  }
}

resource "aws_iam_role" "audit_export_scheduler" {
  name = "${var.name_prefix}-audit-scheduler"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "scheduler.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "audit_export_scheduler" {
  name = "${var.name_prefix}-run-audit-export"
  role = aws_iam_role.audit_export_scheduler.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["ecs:RunTask"]
        Resource = aws_ecs_task_definition.audit_export.arn
        Condition = {
          ArnEquals = { "ecs:cluster" = aws_ecs_cluster.platform.arn }
        }
      },
      {
        Effect   = "Allow"
        Action   = ["iam:PassRole"]
        Resource = [aws_iam_role.ecs_execution.arn, aws_iam_role.audit_export.arn]
        Condition = {
          StringEquals = { "iam:PassedToService" = "ecs-tasks.amazonaws.com" }
        }
      }
    ]
  })
}

resource "aws_scheduler_schedule" "audit_export" {
  name                         = "${var.name_prefix}-audit-export"
  description                  = "Export new application audit records to immutable S3 storage daily."
  schedule_expression          = "cron(45 2 * * ? *)"
  schedule_expression_timezone = "UTC"
  state                        = "ENABLED"

  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = aws_ecs_cluster.platform.arn
    role_arn = aws_iam_role.audit_export_scheduler.arn
    ecs_parameters {
      task_definition_arn = aws_ecs_task_definition.audit_export.arn
      task_count          = 1
      launch_type         = "FARGATE"
      platform_version    = "1.4.0"
      network_configuration {
        assign_public_ip = false
        subnets          = aws_subnet.application[*].id
        security_groups  = [aws_security_group.application.id]
      }
    }
  }
}

resource "aws_sns_topic" "operations" {
  count = var.alarm_email == null ? 0 : 1
  name  = "${var.name_prefix}-operations-alarms"
}

resource "aws_sns_topic_subscription" "operations_email" {
  count     = var.alarm_email == null ? 0 : 1
  topic_arn = aws_sns_topic.operations[0].arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

resource "aws_cloudwatch_event_rule" "scheduled_task_failures" {
  count       = var.alarm_email == null ? 0 : 1
  name        = "${var.name_prefix}-scheduled-task-failures"
  description = "Notify when the daily retention or audit export task exits unsuccessfully."
  event_pattern = jsonencode({
    source        = ["aws.ecs"]
    "detail-type" = ["ECS Task State Change"]
    detail = {
      clusterArn        = [aws_ecs_cluster.platform.arn]
      lastStatus        = ["STOPPED"]
      taskDefinitionArn = [aws_ecs_task_definition.retention.arn, aws_ecs_task_definition.audit_export.arn]
      containers = {
        exitCode = [{ numeric = [">", 0] }]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "scheduled_task_failures" {
  count     = var.alarm_email == null ? 0 : 1
  rule      = aws_cloudwatch_event_rule.scheduled_task_failures[0].name
  target_id = "operations-email"
  arn       = aws_sns_topic.operations[0].arn
}

data "aws_iam_policy_document" "operations_topic" {
  count = var.alarm_email == null ? 0 : 1
  statement {
    sid       = "AllowAccountOwner"
    effect    = "Allow"
    actions   = ["sns:*"]
    resources = [aws_sns_topic.operations[0].arn]
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }
  statement {
    sid       = "AllowScheduledTaskFailureNotifications"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.operations[0].arn]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.scheduled_task_failures[0].arn]
    }
  }
  statement {
    sid       = "AllowCloudWatchAlarmNotifications"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.operations[0].arn]
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:${data.aws_partition.current.partition}:cloudwatch:${var.aws_region}:${data.aws_caller_identity.current.account_id}:alarm:${var.name_prefix}-*"]
    }
  }
}

resource "aws_sns_topic_policy" "operations" {
  count  = var.alarm_email == null ? 0 : 1
  arn    = aws_sns_topic.operations[0].arn
  policy = data.aws_iam_policy_document.operations_topic[0].json
}

resource "aws_cloudwatch_metric_alarm" "api_5xx" {
  alarm_name          = "${var.name_prefix}-api-5xx"
  alarm_description   = "API requests returned server errors."
  namespace           = "AWSMonitoringPlatform"
  metric_name         = "ApiRequests"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 5
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  dimensions          = { Service = "api", StatusClass = "5xx" }
  alarm_actions       = var.alarm_email == null ? [] : [aws_sns_topic.operations[0].arn]
}

resource "aws_cloudwatch_metric_alarm" "api_latency" {
  alarm_name          = "${var.name_prefix}-api-latency-p95"
  alarm_description   = "API p95 request latency is above two seconds."
  namespace           = "AWSMonitoringPlatform"
  metric_name         = "ApiLatency"
  extended_statistic  = "p95"
  period              = 300
  evaluation_periods  = 2
  threshold           = 2000
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  dimensions          = { Service = "api", StatusClass = "2xx" }
  alarm_actions       = var.alarm_email == null ? [] : [aws_sns_topic.operations[0].arn]
}

resource "aws_cloudwatch_metric_alarm" "worker_failures" {
  alarm_name          = "${var.name_prefix}-worker-message-failures"
  alarm_description   = "One or more worker messages failed processing."
  namespace           = "AWSMonitoringPlatform"
  metric_name         = "WorkerMessagesFailed"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  dimensions          = { Service = "worker" }
  alarm_actions       = var.alarm_email == null ? [] : [aws_sns_topic.operations[0].arn]
}

resource "aws_cloudwatch_metric_alarm" "queue_age" {
  alarm_name          = "${var.name_prefix}-queue-oldest-message"
  alarm_description   = "Oldest queued security event has been waiting more than five minutes."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateAgeOfOldestMessage"
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 300
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  dimensions          = { QueueName = module.event_pipeline.events_queue_name }
  alarm_actions       = var.alarm_email == null ? [] : [aws_sns_topic.operations[0].arn]
}

resource "aws_cloudwatch_metric_alarm" "queue_depth" {
  alarm_name          = "${var.name_prefix}-queue-visible-depth"
  alarm_description   = "More than 100 security events are visible in the processing queue."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 2
  threshold           = 100
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  dimensions          = { QueueName = module.event_pipeline.events_queue_name }
  alarm_actions       = var.alarm_email == null ? [] : [aws_sns_topic.operations[0].arn]
}

resource "aws_cloudwatch_metric_alarm" "processing_dlq" {
  alarm_name          = "${var.name_prefix}-processing-dlq"
  alarm_description   = "Messages are present in the worker processing dead-letter queue."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  dimensions          = { QueueName = module.event_pipeline.processing_dlq_name }
  alarm_actions       = var.alarm_email == null ? [] : [aws_sns_topic.operations[0].arn]
}

resource "aws_cloudwatch_metric_alarm" "delivery_dlq" {
  alarm_name          = "${var.name_prefix}-delivery-dlq"
  alarm_description   = "EventBridge delivery failures are present in the delivery dead-letter queue."
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  dimensions          = { QueueName = module.event_pipeline.delivery_dlq_name }
  alarm_actions       = var.alarm_email == null ? [] : [aws_sns_topic.operations[0].arn]
}

resource "aws_cloudwatch_metric_alarm" "database_cpu" {
  alarm_name          = "${var.name_prefix}-database-cpu"
  alarm_description   = "RDS CPU utilization exceeds 80 percent."
  namespace           = "AWS/RDS"
  metric_name         = "CPUUtilization"
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 2
  threshold           = 80
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  dimensions          = { DBInstanceIdentifier = aws_db_instance.platform.id }
  alarm_actions       = var.alarm_email == null ? [] : [aws_sns_topic.operations[0].arn]
}

resource "aws_cloudwatch_metric_alarm" "database_storage" {
  alarm_name          = "${var.name_prefix}-database-free-storage"
  alarm_description   = "RDS free storage has fallen below 10 GiB."
  namespace           = "AWS/RDS"
  metric_name         = "FreeStorageSpace"
  statistic           = "Minimum"
  period              = 300
  evaluation_periods  = 2
  threshold           = 10737418240
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "notBreaching"
  dimensions          = { DBInstanceIdentifier = aws_db_instance.platform.id }
  alarm_actions       = var.alarm_email == null ? [] : [aws_sns_topic.operations[0].arn]
}

resource "aws_cloudwatch_dashboard" "platform" {
  dashboard_name = "${var.name_prefix}-operations"
  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "API requests and latency"
          region = var.aws_region
          view   = "timeSeries"
          metrics = [
            ["AWSMonitoringPlatform", "ApiRequests", "Service", "api", "StatusClass", "2xx"],
            [".", "ApiRequests", "Service", "api", "StatusClass", "5xx"],
            [".", "ApiLatency", "Service", "api", "StatusClass", "2xx", { stat = "p95", yAxis = "right" }]
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          title  = "Queue age and depth"
          region = var.aws_region
          view   = "timeSeries"
          metrics = [
            ["AWS/SQS", "ApproximateAgeOfOldestMessage", "QueueName", module.event_pipeline.events_queue_name],
            [".", "ApproximateNumberOfMessagesVisible", ".", module.event_pipeline.events_queue_name]
          ]
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6
        properties = {
          title  = "Worker failures and RDS capacity"
          region = var.aws_region
          view   = "timeSeries"
          metrics = [
            ["AWSMonitoringPlatform", "WorkerMessagesFailed", "Service", "worker"],
            ["AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", aws_db_instance.platform.id],
            [".", "FreeStorageSpace", ".", aws_db_instance.platform.id]
          ]
        }
      }
    ]
  })
}
