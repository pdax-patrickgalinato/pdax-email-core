locals {
  name = "${var.name_prefix}-${var.environment}"

  tags = {
    Project     = "segs"
    Environment = var.environment
    ManagedBy   = "terraform"
  }

  # AWS-managed "com.amazonaws.global.cloudfront.origin-facing".
  # Hard-coded so apply does not need ec2:GetManagedPrefixListEntries.
  cloudfront_origin_prefix_list_ids = {
    "ap-southeast-1" = "pl-31a34658"
    "ap-southeast-2" = "pl-b8a742d1"
    "us-east-1"      = "pl-3b927c52"
    "us-west-2"      = "pl-82a045eb"
    "eu-west-1"      = "pl-4fa04526"
  }

  cloudfront_origin_prefix_list_id = lookup(
    local.cloudfront_origin_prefix_list_ids,
    var.aws_region,
    "pl-31a34658",
  )

  # SSO assumed-role session ARNs are invalid in KMS key policies.
  # Look up the IAM role so the path (aws-reserved/sso.amazonaws.com/<region>/) is included.
  kms_deploy_principals = [data.aws_iam_role.deploy.arn]

  app_secret_keys = [
    "SEG_GMAIL_USERS",
    "SEG_GMAIL_DOMAIN",
    "SEG_ENFORCE",
    "SEG_CONTENT_PROVIDER",
    "SEG_INTEL_CLIENT",
    "SEG_GLM_MODEL_ID",
    "SEG_GLM_API_KEY",
    "SEG_GLM_PROJECT_ID",
    "SEG_GLM_FALLBACK1_MODEL_ID",
    "SEG_GLM_FALLBACK2_MODEL_ID",
    "SEG_GLM_FALLBACK2_LOCATION",
    "SEG_GLM_FALLBACK3_MODEL_ID",
    "SEG_GLM_FALLBACK3_LOCATION",
    "SEG_VT_API_KEY",
    "SEG_ABUSEIPDB_API_KEY",
    "SEGS_NOTIFY_SMTP_PASS",
    "SEGS_GMAIL_CREDENTIALS_JSON",
  ]

  infra_secret_keys = [
    "SEG_S3_BUCKET",
    "SEG_KMS_KEY_ARN",
    "SEG_DATABASE_URL",
    "SEG_SQS_STATIC_URL",
    "SEG_SQS_CONTENT_AI_URL",
    "SEG_SQS_THREAD_AI_URL",
    "SEG_SQS_CAMPAIGN_URL",
    "SEG_SQS_PROFILE_URL",
    "SEG_JWT_SECRET",
    "SEG_SCIM_BEARER_TOKEN",
    "SEG_TLS_CERT",
    "SEG_TLS_KEY",
    "SEG_TLS_CA",
  ]

  # Per-container only. Operator knobs live in Secrets Manager.
  shared_environment = [
    { name = "SEG_COOKIE_SECURE", value = "1" },
    { name = "SEG_GMAIL_CREDENTIALS", value = "/opt/segs/credentials.json" },
    { name = "SEG_GLM_CREDENTIALS_PATH", value = "/opt/segs/credentials.json" },
    { name = "GOOGLE_APPLICATION_CREDENTIALS", value = "/opt/segs/credentials.json" },
    { name = "AWS_REGION", value = var.aws_region },
  ]

  mime_types = {
    html  = "text/html; charset=utf-8"
    js    = "text/javascript; charset=utf-8"
    css   = "text/css; charset=utf-8"
    json  = "application/json"
    svg   = "image/svg+xml"
    png   = "image/png"
    ico   = "image/x-icon"
    woff  = "font/woff"
    woff2 = "font/woff2"
    map   = "application/json"
    txt   = "text/plain; charset=utf-8"
    webp  = "image/webp"
  }

  console_files = var.sync_console ? fileset(var.console_dist_path, "**") : []

  cloudfront_cache_disabled    = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
  cloudfront_cache_optimized   = "658327ea-f89d-4fab-a63d-7e88639e58f6"
  cloudfront_origin_all_viewer = "b689b0a8-53d0-40ab-baf2-68738e2966ac"
  cloudfront_origin_s3_cors    = "88a5eaf4-2fd4-4709-b370-b4c650ea3fcf"

  # Internal ALB is only reachable through the HTTP API VPC link.
  api_origin_id = var.api_via_apigateway ? "apigw-api" : "alb-api"
}