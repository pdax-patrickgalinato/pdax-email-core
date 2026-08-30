# Split worker tasks (one container per python -m workers <name>).
# Created when worker_image_digest is set. The all-in-one receiver then
# sets SEG_INLINE_WORKERS=0 so poll/static/AI do not run twice.

locals {
  # SQS-backed workers. content_ai / static / sender run several in-process
  # consumers per task; desired_count is the Fargate replica count.
  # gmail_poll / retry stay at 1 (timer or singleton poll).
  # campaign stays at 1 task (recompute rewrites the campaigns table) but
  # runs several in-process SQS consumers.
  workers_scale = {
    static = {
      min    = var.static_min_count
      max    = var.static_max_count
      target = var.static_scale_target
      queue  = "static"
    }
    content_ai = {
      min    = var.content_ai_desired_count
      max    = var.content_ai_max_count
      target = var.content_ai_scale_target
      queue  = "content_ai"
    }
    thread_ai = {
      min    = var.thread_ai_min_count
      max    = var.thread_ai_max_count
      target = var.thread_ai_scale_target
      queue  = "thread_ai"
    }
    sender = {
      min    = var.sender_min_count
      max    = var.sender_max_count
      target = var.sender_scale_target
      queue  = "profile"
    }
    campaign = {
      min    = var.campaign_min_count
      max    = var.campaign_max_count
      target = var.campaign_scale_target
      queue  = "campaign"
    }
  }

  workers = {
    gmail_poll = {
      cpu    = var.poll_cpu
      memory = var.poll_memory
      env    = []
    }
    static = {
      cpu    = var.static_cpu
      memory = var.static_memory
      env = [
        { name = "SEG_STATIC_WORKERS", value = "4" },
      ]
    }
    content_ai = {
      cpu    = var.content_ai_cpu
      memory = var.content_ai_memory
      env = [
        { name = "SEG_CONTENT_AI_WORKERS", value = "8" },
      ]
    }
    thread_ai = {
      cpu    = var.thread_ai_cpu
      memory = var.thread_ai_memory
      env = [
        { name = "SEG_THREAD_AI_WORKERS", value = "4" },
      ]
    }
    retry = {
      cpu    = 256
      memory = 512
      env = [
        { name = "SEG_INCONCLUSIVE_RETRY", value = "1" },
      ]
    }
    campaign = {
      cpu    = var.campaign_cpu
      memory = var.campaign_memory
      env = [
        { name = "SEG_CAMPAIGN_WORKER", value = "1" },
        { name = "SEG_CAMPAIGN_WORKERS", value = "4" },
      ]
    }
    sender = {
      cpu    = var.sender_cpu
      memory = var.sender_memory
      env = [
        { name = "SEG_PROFILE_WORKER", value = "1" },
        { name = "SEG_SENDER_RISK_WORKER", value = "1" },
        { name = "SEG_PROFILE_WORKERS", value = "8" },
        { name = "SEG_SENDER_RISK_WORKERS", value = "4" },
      ]
    }
  }

  # Old split health paths still hit the combined task so the API can probe
  # /profile/health and /sender_risk/health during and after the merge.
  worker_health_aliases = {
    profile     = "sender"
    sender_risk = "sender"
  }
}

resource "aws_cloudwatch_log_group" "worker" {
  name              = "/${var.name_prefix}/worker"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.this.arn
}

resource "aws_ecs_task_definition" "worker" {
  for_each = var.worker_image_digest != "" ? local.workers : {}

  family                   = "${local.name}-${replace(each.key, "_", "-")}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = each.value.cpu
  memory                   = each.value.memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  container_definitions = jsonencode([
    {
      name      = "segs-${replace(each.key, "_", "-")}"
      image     = "${aws_ecr_repository.worker.repository_url}@${var.worker_image_digest}"
      essential = true
      command   = [each.key]
      environment = concat(local.shared_environment, [
        { name = "SEG_WORKER", value = each.key },
        { name = "SEG_GMAIL_POLL_SECONDS", value = tostring(var.gmail_poll_seconds) },
      ], each.value.env)
      portMappings = [{
        containerPort = 8766
        protocol      = "tcp"
      }]
      secrets = local.secret_refs
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.worker.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = each.key
        }
      }
      healthCheck = {
        command     = ["CMD-SHELL", "curl -fk https://localhost:8766/health || exit 1"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 60
      }
      # Fargate max is 120s. Lets an in-flight SQS job finish before SIGKILL
      # on scale-in; visibility timeout still covers a hard kill.
      stopTimeout = contains(keys(local.workers_scale), each.key) ? 120 : 30
    }
  ])
}

resource "aws_ecs_service" "worker" {
  for_each = aws_ecs_task_definition.worker

  name             = "${local.name}-${replace(each.key, "_", "-")}"
  cluster          = aws_ecs_cluster.this.id
  task_definition  = each.value.arn
  desired_count    = contains(keys(local.workers_scale), each.key) ? local.workers_scale[each.key].min : 1
  launch_type      = "FARGATE"
  platform_version = "1.4.0"

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.receiver.id]
    assign_public_ip = var.assign_public_ip
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.worker[each.key].arn
    container_name   = "segs-${replace(each.key, "_", "-")}"
    container_port   = 8766
  }

  health_check_grace_period_seconds = 120

  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  depends_on = [aws_lb_listener.workers_https]

  # SQS autoscaling owns desired_count for static / content_ai / thread_ai / sender.
  # Terraform still sets the initial count; later applies must not clamp the
  # scaler back to min.
  lifecycle {
    ignore_changes = [desired_count]
  }
}
