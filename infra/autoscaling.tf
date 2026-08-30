# SQS target tracking for static / content_ai / thread_ai / sender.
# Autoscaling is off in this account; scale with aws ecs update-service.
# gmail_poll / retry stay at 1. campaign stays at 1 task (table rewrite).

check "content_ai_scale_bounds" {
  assert {
    condition     = var.content_ai_desired_count <= var.content_ai_max_count
    error_message = "content_ai_desired_count (min) must be <= content_ai_max_count."
  }
}

check "static_scale_bounds" {
  assert {
    condition     = var.static_min_count <= var.static_max_count
    error_message = "static_min_count must be <= static_max_count."
  }
}

check "thread_ai_scale_bounds" {
  assert {
    condition     = var.thread_ai_min_count <= var.thread_ai_max_count
    error_message = "thread_ai_min_count must be <= thread_ai_max_count."
  }
}

check "campaign_scale_bounds" {
  assert {
    condition     = var.campaign_min_count <= var.campaign_max_count
    error_message = "campaign_min_count must be <= campaign_max_count."
  }
}

check "sender_scale_bounds" {
  assert {
    condition     = var.sender_min_count <= var.sender_max_count
    error_message = "sender_min_count must be <= sender_max_count."
  }
}

check "aurora_scale_bounds" {
  assert {
    condition     = var.aurora_min_capacity <= var.aurora_max_capacity
    error_message = "aurora_min_capacity must be <= aurora_max_capacity."
  }
}

resource "aws_appautoscaling_target" "worker" {
  for_each = var.worker_image_digest != "" && var.enable_worker_autoscaling ? local.workers_scale : {}

  max_capacity       = each.value.max
  min_capacity       = each.value.min
  resource_id        = "service/${aws_ecs_cluster.this.name}/${aws_ecs_service.worker[each.key].name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
  role_arn           = aws_iam_role.autoscaling.arn
}

resource "aws_appautoscaling_policy" "worker_sqs" {
  for_each = aws_appautoscaling_target.worker

  name               = "${local.name}-${replace(each.key, "_", "-")}-sqs"
  policy_type        = "TargetTrackingScaling"
  resource_id        = each.value.resource_id
  scalable_dimension = each.value.scalable_dimension
  service_namespace  = each.value.service_namespace

  target_tracking_scaling_policy_configuration {
    customized_metric_specification {
      metric_name = "ApproximateNumberOfMessagesVisible"
      namespace   = "AWS/SQS"
      statistic   = "Average"
      unit        = "Count"

      dimensions {
        name  = "QueueName"
        value = aws_sqs_queue.this[local.workers_scale[each.key].queue].name
      }
    }

    target_value       = local.workers_scale[each.key].target
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}
