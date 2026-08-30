# VPC-internal ALB so the API can probe split worker /health over TLS.
# Public internet never reaches this load balancer.

resource "aws_lb" "workers" {
  count = var.worker_image_digest != "" ? 1 : 0

  name               = "${local.name}-workers"
  load_balancer_type = "application"
  internal           = true
  security_groups    = [aws_security_group.workers_alb.id]
  subnets            = aws_subnet.private[*].id

  drop_invalid_header_fields = true
}

resource "aws_lb_target_group" "worker" {
  for_each = var.worker_image_digest != "" ? local.workers : {}

  name        = "${local.name}-${replace(each.key, "_", "-")}-tls"
  port        = 8766
  protocol    = "HTTPS"
  vpc_id      = aws_vpc.this.id
  target_type = "ip"

  health_check {
    enabled             = true
    path                = "/health"
    protocol            = "HTTPS"
    matcher             = "200"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  deregistration_delay = 30

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_lb_listener" "workers_https" {
  count = var.worker_image_digest != "" ? 1 : 0

  load_balancer_arn = aws_lb.workers[0].arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate.internal.arn

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "application/json"
      message_body = "{\"ok\":false}"
      status_code  = "404"
    }
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_lb_listener_rule" "worker" {
  for_each = aws_lb_target_group.worker

  listener_arn = aws_lb_listener.workers_https[0].arn
  priority     = index(sort(keys(local.workers)), each.key) + 1

  action {
    type             = "forward"
    target_group_arn = each.value.arn
  }

  condition {
    path_pattern {
      values = ["/${each.key}", "/${each.key}/*"]
    }
  }
}

resource "aws_lb_listener_rule" "worker_alias" {
  for_each = var.worker_image_digest != "" ? local.worker_health_aliases : {}

  listener_arn = aws_lb_listener.workers_https[0].arn
  priority     = 50 + index(sort(keys(local.worker_health_aliases)), each.key)

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.worker[each.value].arn
  }

  condition {
    path_pattern {
      values = ["/${each.key}", "/${each.key}/*"]
    }
  }
}
