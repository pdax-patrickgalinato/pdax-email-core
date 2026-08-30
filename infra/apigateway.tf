# HTTP API VPC links require AWSServiceRoleForAPIGateway
# (ops.apigateway.amazonaws.com). SSO cannot iam:CreateServiceLinkedRole;
# that role was created once via a Fargate task using esdd-segs-prod-slr.
resource "aws_security_group" "apigw_vpc_link" {
  name        = "${local.name}-apigw-vpclink"
  description = "API Gateway HTTP API VPC link ENIs"
  vpc_id      = aws_vpc.this.id

  egress {
    description = "To API ALB HTTP in this VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }
}

resource "aws_apigatewayv2_vpc_link" "api" {
  name               = "${local.name}-vpclink"
  security_group_ids = [aws_security_group.apigw_vpc_link.id]
  subnet_ids         = aws_subnet.private[*].id
}

# Routes, methods, and the VPC-link integration come from infra/openapi.yaml
# (generated from FastAPI). Do not add aws_apigatewayv2_route resources here —
# undeclared paths 404 at API Gateway instead of reaching the ALB.
resource "aws_apigatewayv2_api" "http" {
  name          = "${local.name}-http"
  protocol_type = "HTTP"
  description   = "SEGS HTTP API — routes and methods from infra/openapi.yaml"
  body = templatefile("${path.module}/openapi.yaml", {
    vpc_link_id      = aws_apigatewayv2_vpc_link.api.id
    alb_listener_arn = aws_lb_listener.api_http.arn
  })
  fail_on_warnings = false
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.http.id
  name        = "$default"
  auto_deploy = true

  default_route_settings {
    throttling_burst_limit = 200
    throttling_rate_limit  = 100
  }
}
