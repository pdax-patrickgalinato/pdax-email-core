data "aws_caller_identity" "current" {}

data "aws_iam_role" "deploy" {
  name = split("/", data.aws_caller_identity.current.arn)[1]
}

resource "aws_security_group" "alb" {
  name = "${local.name}-alb"
  # Keep this string stable — aws_security_group.description is ForceNew.
  description = "API ALB - CloudFront origin-facing prefix list only"
  vpc_id      = aws_vpc.this.id

  dynamic "ingress" {
    for_each = var.api_alb_internal ? [] : [1]
    content {
      description     = "HTTPS from CloudFront"
      from_port       = 443
      to_port         = 443
      protocol        = "tcp"
      prefix_list_ids = [local.cloudfront_origin_prefix_list_id]
    }
  }

  ingress {
    description     = "HTTP from API Gateway VPC link"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.apigw_vpc_link.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "api" {
  name        = "${local.name}-api"
  description = "API Fargate tasks"
  vpc_id      = aws_vpc.this.id

  ingress {
    description     = "From API ALB"
    from_port       = 8765
    to_port         = 8765
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "workers_alb" {
  name        = "${local.name}-workers-alb"
  description = "Internal workers ALB - API tasks only"
  vpc_id      = aws_vpc.this.id

  ingress {
    description     = "HTTPS from API"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.api.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "receiver" {
  name        = "${local.name}-receiver"
  description = "Gmail poller Fargate tasks - no inbound"
  vpc_id      = aws_vpc.this.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_vpc_security_group_ingress_rule" "receiver_health" {
  security_group_id            = aws_security_group.receiver.id
  description                  = "Health from workers ALB"
  from_port                    = 8766
  to_port                      = 8766
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.workers_alb.id
}

resource "aws_security_group" "aurora" {
  name        = "${local.name}-aurora"
  description = "Aurora PostgreSQL from API and worker tasks"
  vpc_id      = aws_vpc.this.id

  ingress {
    description     = "Postgres from API"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.api.id]
  }

  ingress {
    description     = "Postgres from receiver/workers"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.receiver.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
