resource "aws_secretsmanager_secret" "prod" {
  name                    = "${var.name_prefix}/${var.environment}/app"
  description             = "SEGS operator secrets (credentials.json, API keys). Values via put-secrets.sh."
  recovery_window_in_days = 7
  kms_key_id              = aws_kms_key.this.arn
}

resource "aws_secretsmanager_secret" "infra" {
  name                    = "${var.name_prefix}/${var.environment}/infra"
  description             = "SEGS Terraform-owned infra URLs (S3, SQS, KMS, DATABASE_URL)."
  recovery_window_in_days = 7
  kms_key_id              = aws_kms_key.this.arn
}

data "aws_iam_policy_document" "ecs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "execution" {
  # Sandbox IAM allows iam:PassRole only on role/esdd-* for ecs-tasks.
  name               = "esdd-${local.name}-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json

  lifecycle {
    create_before_destroy = true
  }
}

data "aws_iam_policy_document" "execution" {
  statement {
    sid = "EcrPull"
    actions = [
      "ecr:GetAuthorizationToken",
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
    ]
    resources = ["*"]
  }

  statement {
    sid = "Logs"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/${var.name_prefix}/*"]
  }

  statement {
    sid     = "ReadSecrets"
    actions = ["secretsmanager:GetSecretValue"]
    resources = [
      aws_secretsmanager_secret.prod.arn,
      aws_secretsmanager_secret.infra.arn,
    ]
  }

  statement {
    sid = "DecryptCmk"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
    ]
    resources = [aws_kms_key.this.arn]
  }
}

resource "aws_iam_role_policy" "execution" {
  name   = "${local.name}-execution"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.execution.json
}

resource "aws_iam_role" "task" {
  # Sandbox IAM allows iam:PassRole only on role/esdd-* for ecs-tasks.
  name               = "esdd-${local.name}-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json

  lifecycle {
    create_before_destroy = true
  }
}

data "aws_iam_policy_document" "task" {
  statement {
    sid = "MailObjects"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
      "s3:AbortMultipartUpload",
    ]
    resources = [
      "${aws_s3_bucket.mail.arn}/spool/*",
      "${aws_s3_bucket.mail.arn}/cache/*",
      "${aws_s3_bucket.mail.arn}/logs/*",
    ]
  }

  statement {
    sid       = "ListMailBucket"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.mail.arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["spool/", "spool/*", "cache/", "cache/*", "logs/", "logs/*"]
    }
  }

  statement {
    sid = "Queues"
    actions = [
      "sqs:SendMessage",
      "sqs:ReceiveMessage",
      "sqs:DeleteMessage",
      "sqs:ChangeMessageVisibility",
      "sqs:GetQueueUrl",
      "sqs:GetQueueAttributes",
    ]
    resources = concat(
      [for q in aws_sqs_queue.this : q.arn],
      [for q in aws_sqs_queue.dlq : q.arn],
    )
  }

  statement {
    sid = "CmkDataKeys"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:GenerateDataKey",
      "kms:GenerateDataKeyWithoutPlaintext",
      "kms:DescribeKey",
    ]
    resources = [aws_kms_key.this.arn]
  }
}

resource "aws_iam_role_policy" "task" {
  name   = "${local.name}-task"
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.task.json
}

# Sandbox SSO cannot iam:CreateServiceLinkedRole. Application Auto Scaling
# still accepts a customer role on RegisterScalableTarget if we PassRole it.
data "aws_iam_policy_document" "autoscaling_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["application-autoscaling.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "autoscaling" {
  name               = "esdd-${local.name}-autoscaling"
  assume_role_policy = data.aws_iam_policy_document.autoscaling_assume.json
}

data "aws_iam_policy_document" "autoscaling" {
  statement {
    sid = "EcsService"
    actions = [
      "ecs:DescribeServices",
      "ecs:UpdateService",
    ]
    resources = [
      "arn:aws:ecs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:service/${aws_ecs_cluster.this.name}/*",
    ]
  }

  statement {
    sid = "Alarms"
    actions = [
      "cloudwatch:DescribeAlarms",
      "cloudwatch:GetMetricData",
      "cloudwatch:PutMetricAlarm",
      "cloudwatch:DeleteAlarms",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "autoscaling" {
  name   = "${local.name}-autoscaling"
  role   = aws_iam_role.autoscaling.id
  policy = data.aws_iam_policy_document.autoscaling.json
}
