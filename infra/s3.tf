resource "aws_s3_bucket" "console" {
  bucket = "${local.name}-console-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_public_access_block" "console" {
  bucket = aws_s3_bucket.console.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "console" {
  bucket = aws_s3_bucket.console.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "console" {
  bucket = aws_s3_bucket.console.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_ownership_controls" "console" {
  bucket = aws_s3_bucket.console.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_cloudfront_origin_access_control" "console" {
  name                              = "${local.name}-console"
  description                       = "OAC for SEGS web console"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

data "aws_iam_policy_document" "console_oac" {
  statement {
    sid     = "AllowCloudFrontOAC"
    actions = ["s3:GetObject"]
    resources = [
      "${aws_s3_bucket.console.arn}/*",
    ]
    principals {
      type        = "Service"
      identifiers = ["cloudfront.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceArn"
      values   = [aws_cloudfront_distribution.console.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "console" {
  bucket = aws_s3_bucket.console.id
  policy = data.aws_iam_policy_document.console_oac.json
}

resource "aws_s3_object" "console" {
  for_each = toset(local.console_files)

  bucket = aws_s3_bucket.console.id
  key    = each.value
  source = "${var.console_dist_path}/${each.value}"
  etag   = filemd5("${var.console_dist_path}/${each.value}")
  content_type = lookup(
    local.mime_types,
    lower(element(reverse(split(".", each.value)), 0)),
    "application/octet-stream",
  )
  cache_control = startswith(each.value, "assets/") ? "public, max-age=31536000, immutable" : "no-cache"
}

resource "aws_s3_bucket" "mail" {
  bucket = "${local.name}-mail-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_public_access_block" "mail" {
  bucket = aws_s3_bucket.mail.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "mail" {
  bucket = aws_s3_bucket.mail.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.this.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "mail" {
  bucket = aws_s3_bucket.mail.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_ownership_controls" "mail" {
  bucket = aws_s3_bucket.mail.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "mail" {
  bucket = aws_s3_bucket.mail.id

  rule {
    id     = "abort-incomplete"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  rule {
    id     = "ia-released-rejected"
    status = "Enabled"
    filter {
      prefix = "spool/released/"
    }
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
  }

  rule {
    id     = "ia-rejected"
    status = "Enabled"
    filter {
      prefix = "spool/rejected/"
    }
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
  }
}

data "aws_iam_policy_document" "mail" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.mail.arn,
      "${aws_s3_bucket.mail.arn}/*",
    ]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid       = "DenyUnencryptedPuts"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.mail.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }

  statement {
    sid       = "DenyWrongCmk"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.mail.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [aws_kms_key.this.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "mail" {
  bucket = aws_s3_bucket.mail.id
  policy = data.aws_iam_policy_document.mail.json
}
