# API ALB is VPC-internal. Public path is already TLS:
#   CloudFront → HTTP API (execute-api) → VPC link.
# API Gateway VPC links send plaintext HTTP to the ALB listener, so this
# listener stays HTTP:80. The target group is HTTPS — ALB opens TLS to
# Fargate :8765. Workers ALB is HTTPS end-to-end (the API is a real TLS client).
# Set api_alb_internal=false only for the one-time cutover while the VPC link
# is created.
resource "aws_lb" "api" {
  name               = "${local.name}-api"
  load_balancer_type = "application"
  internal           = var.api_alb_internal
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.api_alb_internal ? aws_subnet.private[*].id : aws_subnet.public[*].id
  idle_timeout       = 301

  drop_invalid_header_fields = true
}

resource "aws_lb_target_group" "api" {
  name        = "${local.name}-api-tls"
  port        = 8765
  protocol    = "HTTPS"
  vpc_id      = aws_vpc.this.id
  target_type = "ip"

  health_check {
    enabled             = true
    path                = "/api/health"
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

resource "aws_lb_listener" "api_http" {
  load_balancer_arn = aws_lb.api.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}
