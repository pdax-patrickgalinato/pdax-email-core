locals {
  secret_refs = concat(
    [
      for key in local.app_secret_keys : {
        name      = key
        valueFrom = "${aws_secretsmanager_secret.prod.arn}:${key}::"
      }
    ],
    [
      for key in local.infra_secret_keys : {
        name      = key
        valueFrom = "${aws_secretsmanager_secret.infra.arn}:${key}::"
      }
    ],
  )
}

resource "aws_ecs_cluster" "this" {
  name = local.name

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_ecs_task_definition" "api" {
  count = var.api_image_digest != "" ? 1 : 0

  family                   = "${local.name}-api"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.api_cpu
  memory                   = var.api_memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  container_definitions = jsonencode([
    {
      name      = "segs-api"
      image     = "${aws_ecr_repository.api.repository_url}@${var.api_image_digest}"
      essential = true
      portMappings = [{
        containerPort = 8765
        protocol      = "tcp"
      }]
      environment = concat(
        local.shared_environment,
        [
          { name = "SEG_SERVE_SPA", value = "0" },
          { name = "SEG_PROFILE_WORKER", value = "0" },
          { name = "SEG_CAMPAIGN_WORKER", value = "0" },
          { name = "SEG_SENDER_RISK_WORKER", value = "0" },
          { name = "SEG_INCONCLUSIVE_RETRY", value = "0" },
          { name = "SEG_INLINE_WORKERS", value = "0" },
          { name = "SEG_PUBLIC_ORIGIN", value = "https://${aws_cloudfront_distribution.console.domain_name}" },
        ],
        length(aws_lb.workers) > 0 ? [{
          name  = "SEG_WORKER_HEALTH_BASE_URL"
          value = "https://${aws_lb.workers[0].dns_name}"
        }] : [],
      )
      secrets = local.secret_refs
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.api.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "segs"
        }
      }
      healthCheck = {
        command     = ["CMD-SHELL", "curl -fk https://localhost:8765/api/health || exit 1"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 60
      }
    }
  ])
}

resource "aws_ecs_task_definition" "receiver" {
  count = var.receiver_image_digest != "" ? 1 : 0

  family                   = "${local.name}-receiver"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.receiver_cpu
  memory                   = var.receiver_memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  container_definitions = jsonencode([
    {
      name      = "segs-receiver"
      image     = "${aws_ecr_repository.receiver.repository_url}@${var.receiver_image_digest}"
      essential = true
      portMappings = [{
        containerPort = 8766
        protocol      = "tcp"
      }]
      environment = concat(local.shared_environment, [
        { name = "SEG_GMAIL_POLL_SECONDS", value = tostring(var.gmail_poll_seconds) },
        { name = "SEG_INLINE_WORKERS", value = var.worker_image_digest != "" ? "0" : "1" },
      ])
      secrets = local.secret_refs
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.receiver.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "segs"
        }
      }
      healthCheck = {
        command     = ["CMD-SHELL", "curl -fk https://localhost:8766/health || exit 1"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 20
      }
    }
  ])
}

resource "aws_ecs_service" "api" {
  count = var.api_image_digest != "" ? 1 : 0

  name             = "${local.name}-api"
  cluster          = aws_ecs_cluster.this.id
  task_definition  = aws_ecs_task_definition.api[0].arn
  desired_count    = var.api_desired_count
  launch_type      = "FARGATE"
  platform_version = "1.4.0"

  enable_execute_command = false

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.api.id]
    assign_public_ip = var.assign_public_ip
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.api.arn
    container_name   = "segs-api"
    container_port   = 8765
  }

  health_check_grace_period_seconds = 120

  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  depends_on = [aws_lb_listener.api_http]
}

resource "aws_ecs_service" "receiver" {
  count = var.receiver_image_digest != "" ? 1 : 0

  name             = "${local.name}-receiver"
  cluster          = aws_ecs_cluster.this.id
  task_definition  = aws_ecs_task_definition.receiver[0].arn
  desired_count    = var.receiver_desired_count
  launch_type      = "FARGATE"
  platform_version = "1.4.0"

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.receiver.id]
    assign_public_ip = var.assign_public_ip
  }
}
