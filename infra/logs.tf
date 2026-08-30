resource "aws_cloudwatch_log_group" "api" {
  name              = "/${var.name_prefix}/api"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.this.arn
}

resource "aws_cloudwatch_log_group" "receiver" {
  name              = "/${var.name_prefix}/receiver"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.this.arn
}
