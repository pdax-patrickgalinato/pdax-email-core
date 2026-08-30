resource "random_password" "db" {
  length  = 32
  special = false
}

resource "random_password" "jwt" {
  length  = 48
  special = false
}

resource "random_password" "scim" {
  length  = 48
  special = false
}

resource "aws_db_subnet_group" "this" {
  name       = "${local.name}-aurora"
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_rds_cluster" "this" {
  cluster_identifier = "${local.name}-pg"
  engine             = "aurora-postgresql"
  engine_version     = "16.8"
  engine_mode        = "provisioned"
  database_name      = "segs"
  master_username    = "segs"
  master_password    = random_password.db.result
  storage_encrypted  = true
  kms_key_id         = aws_kms_key.this.arn

  serverlessv2_scaling_configuration {
    min_capacity = var.aurora_min_capacity
    max_capacity = var.aurora_max_capacity
  }

  db_subnet_group_name    = aws_db_subnet_group.this.name
  vpc_security_group_ids  = [aws_security_group.aurora.id]
  backup_retention_period = 1
  skip_final_snapshot     = true
  deletion_protection     = false
  enable_http_endpoint    = false
  apply_immediately       = true
  copy_tags_to_snapshot   = true
}

resource "aws_secretsmanager_secret_version" "infra" {
  secret_id = aws_secretsmanager_secret.infra.id
  secret_string = jsonencode({
    SEG_S3_BUCKET          = aws_s3_bucket.mail.bucket
    SEG_KMS_KEY_ARN        = aws_kms_key.this.arn
    SEG_DATABASE_URL       = "postgresql://segs:${urlencode(random_password.db.result)}@${aws_rds_cluster.this.endpoint}:5432/segs?sslmode=require"
    SEG_SQS_STATIC_URL     = aws_sqs_queue.this["static"].url
    SEG_SQS_CONTENT_AI_URL = aws_sqs_queue.this["content_ai"].url
    SEG_SQS_THREAD_AI_URL  = aws_sqs_queue.this["thread_ai"].url
    SEG_SQS_CAMPAIGN_URL   = aws_sqs_queue.this["campaign"].url
    SEG_SQS_PROFILE_URL    = aws_sqs_queue.this["profile"].url
    SEG_JWT_SECRET         = random_password.jwt.result
    SEG_SCIM_BEARER_TOKEN  = random_password.scim.result
    SEG_TLS_CERT           = tls_locally_signed_cert.internal.cert_pem
    SEG_TLS_KEY            = tls_private_key.internal.private_key_pem
    SEG_TLS_CA             = tls_self_signed_cert.ca.cert_pem
  })
}

resource "aws_rds_cluster_instance" "writer" {
  identifier                   = "${local.name}-pg-writer"
  cluster_identifier           = aws_rds_cluster.this.id
  instance_class               = "db.serverless"
  engine                       = aws_rds_cluster.this.engine
  engine_version               = aws_rds_cluster.this.engine_version
  publicly_accessible          = false
  performance_insights_enabled = false
  monitoring_interval          = 0
}
