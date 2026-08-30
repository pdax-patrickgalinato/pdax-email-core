# CloudWatch dashboard + a small set of alarms for the SEGS pipeline.
# Open via `terraform output dashboard_url`.

locals {
  dashboard_ecs_services = compact(concat(
    var.api_image_digest != "" ? ["${local.name}-api"] : [],
    var.receiver_image_digest != "" && var.receiver_desired_count > 0 ? ["${local.name}-receiver"] : [],
    var.worker_image_digest != "" ? [
      for k in sort(keys(local.workers)) : "${local.name}-${replace(k, "_", "-")}"
    ] : [],
  ))

  dashboard_widgets = concat(
    [
      {
        type   = "text"
        x      = 0
        y      = 0
        width  = 24
        height = 2
        properties = {
          markdown = <<-MD
            # ${local.name} pipeline
            SQS-backed workers (`static`, `content_ai`, `thread_ai`) autoscale on visible messages. `gmail_poll` is a singleton. Watch Aurora ACU vs `aurora_max_capacity` before adding content_ai tasks.
          MD
        }
      },
      {
        type   = "alarm"
        x      = 0
        y      = 2
        width  = 24
        height = 3
        properties = {
          title  = "Alarms"
          alarms = local.dashboard_alarm_arns
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 5
        width  = 12
        height = 6
        properties = {
          title  = "SQS visible (waiting)"
          region = var.aws_region
          stat   = "Average"
          period = 60
          view   = "timeSeries"
          yAxis  = { left = { min = 0 } }
          metrics = [
            for k, q in aws_sqs_queue.this : [
              "AWS/SQS", "ApproximateNumberOfMessagesVisible", "QueueName", q.name,
              { label = k }
            ]
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 5
        width  = 12
        height = 6
        properties = {
          title  = "SQS in flight (not visible)"
          region = var.aws_region
          stat   = "Average"
          period = 60
          view   = "timeSeries"
          yAxis  = { left = { min = 0 } }
          metrics = [
            for k, q in aws_sqs_queue.this : [
              "AWS/SQS", "ApproximateNumberOfMessagesNotVisible", "QueueName", q.name,
              { label = k }
            ]
          ]
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 11
        width  = 12
        height = 6
        properties = {
          title  = "SQS age of oldest message (seconds)"
          region = var.aws_region
          stat   = "Maximum"
          period = 60
          view   = "timeSeries"
          yAxis  = { left = { min = 0 } }
          metrics = [
            for k, q in aws_sqs_queue.this : [
              "AWS/SQS", "ApproximateAgeOfOldestMessage", "QueueName", q.name,
              { label = k }
            ]
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 11
        width  = 12
        height = 6
        properties = {
          title  = "SQS DLQ visible"
          region = var.aws_region
          stat   = "Maximum"
          period = 60
          view   = "timeSeries"
          yAxis  = { left = { min = 0 } }
          metrics = [
            for k, q in aws_sqs_queue.dlq : [
              "AWS/SQS", "ApproximateNumberOfMessagesVisible", "QueueName", q.name,
              { label = k }
            ]
          ]
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 17
        width  = 12
        height = 6
        properties = {
          title  = "ECS CPU %"
          region = var.aws_region
          stat   = "Average"
          period = 60
          view   = "timeSeries"
          yAxis  = { left = { min = 0, max = 100 } }
          metrics = [
            for svc in local.dashboard_ecs_services : [
              "AWS/ECS", "CPUUtilization", "ClusterName", aws_ecs_cluster.this.name, "ServiceName", svc,
              { label = replace(svc, "${local.name}-", "") }
            ]
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 17
        width  = 12
        height = 6
        properties = {
          title  = "ECS memory %"
          region = var.aws_region
          stat   = "Average"
          period = 60
          view   = "timeSeries"
          yAxis  = { left = { min = 0, max = 100 } }
          metrics = [
            for svc in local.dashboard_ecs_services : [
              "AWS/ECS", "MemoryUtilization", "ClusterName", aws_ecs_cluster.this.name, "ServiceName", svc,
              { label = replace(svc, "${local.name}-", "") }
            ]
          ]
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 23
        width  = 12
        height = 6
        properties = {
          title  = "Running tasks (Container Insights)"
          region = var.aws_region
          stat   = "Average"
          period = 60
          view   = "timeSeries"
          yAxis  = { left = { min = 0 } }
          metrics = [
            for svc in local.dashboard_ecs_services : [
              "ECS/ContainerInsights", "RunningTaskCount", "ClusterName", aws_ecs_cluster.this.name, "ServiceName", svc,
              { label = replace(svc, "${local.name}-", "") }
            ]
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 23
        width  = 12
        height = 6
        properties = {
          title  = "API ALB"
          region = var.aws_region
          period = 60
          view   = "timeSeries"
          metrics = [
            ["AWS/ApplicationELB", "RequestCount", "LoadBalancer", aws_lb.api.arn_suffix, { stat = "Sum", label = "requests" }],
            [".", "HTTPCode_Target_2XX_Count", ".", ".", { stat = "Sum", label = "2xx" }],
            [".", "HTTPCode_Target_4XX_Count", ".", ".", { stat = "Sum", label = "4xx" }],
            [".", "HTTPCode_Target_5XX_Count", ".", ".", { stat = "Sum", label = "5xx" }],
            [".", "TargetResponseTime", ".", ".", { stat = "p95", label = "p95 latency", yAxis = "right" }],
            ["AWS/ApplicationELB", "HealthyHostCount", "TargetGroup", aws_lb_target_group.api.arn_suffix, "LoadBalancer", aws_lb.api.arn_suffix, { stat = "Average", label = "healthy hosts" }],
          ]
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 29
        width  = 12
        height = 6
        properties = {
          title  = "Aurora ACU"
          region = var.aws_region
          period = 60
          view   = "timeSeries"
          yAxis = {
            left  = { min = 0, max = var.aurora_max_capacity }
            right = { min = 0, max = 100 }
          }
          annotations = {
            horizontal = [
              {
                label = "max ACU"
                value = var.aurora_max_capacity
                color = "#d62728"
              }
            ]
          }
          metrics = [
            ["AWS/RDS", "ServerlessDatabaseCapacity", "DBClusterIdentifier", aws_rds_cluster.this.cluster_identifier, { stat = "Average", label = "ACU", yAxis = "left" }],
            [".", "ACUUtilization", ".", ".", { stat = "Average", label = "ACU %", yAxis = "right" }],
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 29
        width  = 12
        height = 6
        properties = {
          title  = "Aurora connections"
          region = var.aws_region
          period = 60
          view   = "timeSeries"
          yAxis  = { left = { min = 0 } }
          metrics = [
            ["AWS/RDS", "DatabaseConnections", "DBClusterIdentifier", aws_rds_cluster.this.cluster_identifier, { stat = "Average", label = "connections" }],
            [".", "Deadlocks", ".", ".", { stat = "Sum", label = "deadlocks" }],
            [".", "LoginFailures", ".", ".", { stat = "Sum", label = "login failures" }],
          ]
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 35
        width  = 12
        height = 6
        properties = {
          title  = "Aurora latency (seconds)"
          region = var.aws_region
          stat   = "Average"
          period = 60
          view   = "timeSeries"
          yAxis  = { left = { min = 0 } }
          metrics = [
            ["AWS/RDS", "ReadLatency", "DBClusterIdentifier", aws_rds_cluster.this.cluster_identifier, { label = "read" }],
            [".", "WriteLatency", ".", ".", { label = "write" }],
            [".", "CommitLatency", ".", ".", { label = "commit" }],
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 35
        width  = 12
        height = 6
        properties = {
          title  = "Aurora I/O"
          region = var.aws_region
          period = 60
          view   = "timeSeries"
          yAxis = {
            left  = { min = 0 }
            right = { min = 0, max = 100 }
          }
          metrics = [
            ["AWS/RDS", "VolumeReadIOPs", "DBClusterIdentifier", aws_rds_cluster.this.cluster_identifier, { stat = "Average", label = "volume read IOPS", yAxis = "left" }],
            [".", "VolumeWriteIOPs", ".", ".", { stat = "Average", label = "volume write IOPS", yAxis = "left" }],
            ["AWS/RDS", "BufferCacheHitRatio", "DBInstanceIdentifier", aws_rds_cluster_instance.writer.identifier, { stat = "Average", label = "buffer cache hit %", yAxis = "right" }],
          ]
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 41
        width  = 12
        height = 6
        properties = {
          title  = "Aurora writer CPU & memory"
          region = var.aws_region
          period = 60
          view   = "timeSeries"
          yAxis = {
            left  = { min = 0, max = 100 }
            right = { min = 0 }
          }
          metrics = [
            ["AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", aws_rds_cluster_instance.writer.identifier, { stat = "Average", label = "CPU %", yAxis = "left" }],
            [".", "FreeableMemory", ".", ".", { stat = "Average", label = "freeable memory", yAxis = "right" }],
            [".", "SwapUsage", ".", ".", { stat = "Average", label = "swap", yAxis = "right" }],
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 41
        width  = 12
        height = 6
        properties = {
          title  = "NAT Gateway bytes"
          region = var.aws_region
          stat   = "Sum"
          period = 60
          view   = "timeSeries"
          metrics = [
            ["AWS/NATGateway", "BytesOutToDestination", "NatGatewayId", aws_nat_gateway.this.id, { label = "out to dest" }],
            [".", "BytesInFromSource", ".", ".", { label = "in from VPC" }],
            [".", "BytesInFromDestination", ".", ".", { label = "in from dest" }],
          ]
        }
      },
      {
        type   = "log"
        x      = 0
        y      = 47
        width  = 24
        height = 6
        properties = {
          title  = "Worker errors"
          region = var.aws_region
          view   = "table"
          query  = "SOURCE '${aws_cloudwatch_log_group.worker.name}' | fields @timestamp, @message | filter @message like /ERROR|Exception|Traceback|failed/ | sort @timestamp desc | limit 40"
        }
      },
    ],
    length(aws_lb.workers) > 0 ? [
      {
        type   = "metric"
        x      = 0
        y      = 53
        width  = 24
        height = 5
        properties = {
          title  = "Worker ALB healthy hosts"
          region = var.aws_region
          stat   = "Average"
          period = 60
          view   = "timeSeries"
          yAxis  = { left = { min = 0 } }
          metrics = [
            for k, tg in aws_lb_target_group.worker : [
              "AWS/ApplicationELB", "HealthyHostCount",
              "TargetGroup", tg.arn_suffix,
              "LoadBalancer", aws_lb.workers[0].arn_suffix,
              { label = k }
            ]
          ]
        }
      }
    ] : [],
  )

  dashboard_alarm_arns = concat(
    [for a in aws_cloudwatch_metric_alarm.sqs_dlq : a.arn],
    [
      aws_cloudwatch_metric_alarm.sqs_age["static"].arn,
      aws_cloudwatch_metric_alarm.sqs_age["content_ai"].arn,
      aws_cloudwatch_metric_alarm.api_5xx.arn,
      aws_cloudwatch_metric_alarm.api_healthy.arn,
      aws_cloudwatch_metric_alarm.aurora_acu.arn,
    ],
  )
}

resource "aws_cloudwatch_dashboard" "this" {
  dashboard_name = local.name
  dashboard_body = jsonencode({ widgets = local.dashboard_widgets })
}

resource "aws_cloudwatch_metric_alarm" "sqs_dlq" {
  for_each = aws_sqs_queue.dlq

  alarm_name          = "${local.name}-dlq-${replace(each.key, "_", "-")}"
  alarm_description   = "Messages on the ${each.key} DLQ. Pipeline jobs exhausted 8 receives."
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 60
  statistic           = "Maximum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    QueueName = each.value.name
  }
}

resource "aws_cloudwatch_metric_alarm" "sqs_age" {
  for_each = {
    static     = 300
    content_ai = 600
  }

  alarm_name          = "${local.name}-age-${replace(each.key, "_", "-")}"
  alarm_description   = "Oldest ${each.key} message is older than ${each.value}s. Workers are behind."
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "ApproximateAgeOfOldestMessage"
  namespace           = "AWS/SQS"
  period              = 60
  statistic           = "Maximum"
  threshold           = each.value
  treat_missing_data  = "notBreaching"

  dimensions = {
    QueueName = aws_sqs_queue.this[each.key].name
  }
}

resource "aws_cloudwatch_metric_alarm" "api_5xx" {
  alarm_name          = "${local.name}-api-5xx"
  alarm_description   = "API target 5xx from the public ALB."
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "HTTPCode_Target_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Sum"
  threshold           = 5
  treat_missing_data  = "notBreaching"

  dimensions = {
    LoadBalancer = aws_lb.api.arn_suffix
    TargetGroup  = aws_lb_target_group.api.arn_suffix
  }
}

resource "aws_cloudwatch_metric_alarm" "api_healthy" {
  alarm_name          = "${local.name}-api-healthy"
  alarm_description   = "Fewer healthy API tasks than desired_count."
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "HealthyHostCount"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Average"
  threshold           = var.api_desired_count
  treat_missing_data  = "breaching"

  dimensions = {
    LoadBalancer = aws_lb.api.arn_suffix
    TargetGroup  = aws_lb_target_group.api.arn_suffix
  }
}

resource "aws_cloudwatch_metric_alarm" "aurora_acu" {
  alarm_name          = "${local.name}-aurora-acu"
  alarm_description   = "Aurora ACU utilization is high. Raise aurora_max_capacity before adding content_ai tasks."
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "ACUUtilization"
  namespace           = "AWS/RDS"
  period              = 60
  statistic           = "Average"
  threshold           = 80
  treat_missing_data  = "notBreaching"

  dimensions = {
    DBClusterIdentifier = aws_rds_cluster.this.cluster_identifier
  }
}
