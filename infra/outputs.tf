output "console_url" {
  description = "HTTPS URL for the SOC console (CloudFront default cert — no Route 53)."
  value       = "https://${aws_cloudfront_distribution.console.domain_name}"
}

output "api_origin_dns" {
  description = "ALB DNS. VPC-link target; not for browsers."
  value       = aws_lb.api.dns_name
}

output "api_gateway_invoke_url" {
  description = "HTTP API execute-api hostname. CloudFront /api* and /scim* use this origin."
  value       = "https://${aws_apigatewayv2_api.http.id}.execute-api.${var.aws_region}.amazonaws.com"
}

output "scim_base_url" {
  description = "SCIM 2.0 base URL for JumpCloud (same CloudFront host as the console)."
  value       = "https://${aws_cloudfront_distribution.console.domain_name}/scim/v2"
}

output "workers_alb_dns" {
  description = "Internal workers ALB DNS. API probes http://<this>/{name}/health. Empty when split workers are not deployed."
  value       = length(aws_lb.workers) > 0 ? aws_lb.workers[0].dns_name : ""
}

output "ecr_api_url" {
  value = aws_ecr_repository.api.repository_url
}

output "ecr_worker_url" {
  value = aws_ecr_repository.worker.repository_url
}

output "ecr_receiver_url" {
  value = aws_ecr_repository.receiver.repository_url
}

output "secrets_arn" {
  description = "App secret ARN (operator keys + credentials.json)."
  value       = aws_secretsmanager_secret.prod.arn
}

output "infra_secrets_arn" {
  description = "Infra secret ARN (S3, SQS, KMS, DATABASE_URL)."
  value       = aws_secretsmanager_secret.infra.arn
}

output "cluster_name" {
  value = aws_ecs_cluster.this.name
}

output "kms_key_arn" {
  value = aws_kms_key.this.arn
}

output "kms_alias" {
  value = aws_kms_alias.this.name
}

output "mail_bucket" {
  value = aws_s3_bucket.mail.bucket
}

output "sqs_queue_urls" {
  value = { for k, q in aws_sqs_queue.this : k => q.url }
}

output "aurora_endpoint" {
  description = "VPC-private Aurora writer endpoint."
  value       = aws_rds_cluster.this.endpoint
}

output "vpc_id" {
  description = "Dedicated SEGS VPC. Not the account default VPC."
  value       = aws_vpc.this.id
}

output "public_subnet_ids" {
  value = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  value = aws_subnet.private[*].id
}

output "nat_gateway_id" {
  value = aws_nat_gateway.this.id
}

output "dashboard_name" {
  value = aws_cloudwatch_dashboard.this.dashboard_name
}

output "dashboard_url" {
  description = "CloudWatch dashboard for ECS, SQS, ALB, and Aurora."
  value       = "https://${var.aws_region}.console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${aws_cloudwatch_dashboard.this.dashboard_name}"
}
