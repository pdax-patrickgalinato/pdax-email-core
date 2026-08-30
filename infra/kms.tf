data "aws_iam_policy_document" "cmk" {
  statement {
    sid     = "EnableAccountRoot"
    actions = ["kms:*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    resources = ["*"]
  }

  statement {
    sid     = "AllowDeployCaller"
    actions = ["kms:*"]
    principals {
      type        = "AWS"
      identifiers = local.kms_deploy_principals
    }
    resources = ["*"]
  }

  statement {
    sid = "ExecutionDecryptSecrets"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
    ]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.execution.arn]
    }
    resources = ["*"]
  }

  statement {
    sid = "TaskEncryptDecryptData"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:GenerateDataKey",
      "kms:GenerateDataKeyWithoutPlaintext",
      "kms:DescribeKey",
    ]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.task.arn]
    }
    resources = ["*"]
  }

  statement {
    sid = "LogsUseOfCmk"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]
    principals {
      type        = "Service"
      identifiers = ["logs.${var.aws_region}.amazonaws.com"]
    }
    resources = ["*"]
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values = [
        "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/${var.name_prefix}/*",
      ]
    }
  }

  statement {
    sid = "SecretsManagerUseOfCmk"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:CreateGrant",
      "kms:DescribeKey",
    ]
    principals {
      type        = "Service"
      identifiers = ["secretsmanager.amazonaws.com"]
    }
    resources = ["*"]
  }

  statement {
    sid = "RdsUseOfCmk"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:CreateGrant",
      "kms:DescribeKey",
    ]
    principals {
      type        = "Service"
      identifiers = ["rds.amazonaws.com"]
    }
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["rds.${var.aws_region}.amazonaws.com"]
    }
  }
}

resource "aws_kms_key" "this" {
  description             = "SEGS project CMK — S3, SQS, Aurora, Secrets Manager, CloudWatch Logs"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.cmk.json
}

resource "aws_kms_alias" "this" {
  name          = "alias/${var.name_prefix}-${var.environment}"
  target_key_id = aws_kms_key.this.key_id
}
