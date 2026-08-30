variable "aws_region" {
  type        = string
  description = "Region for all resources except the CloudFront WAF."
  default     = "ap-southeast-1"
}

variable "environment" {
  type        = string
  description = "Name stamped on resources (prod, staging, …)."
  default     = "prod"
}

variable "name_prefix" {
  type        = string
  description = "Short prefix for resource names."
  default     = "segs"
}

variable "vpc_cidr" {
  type        = string
  description = "CIDR for the dedicated SEGS VPC. Must not be the account default VPC (172.31.0.0/16)."
  default     = "10.80.0.0/16"

  validation {
    condition     = can(cidrnetmask(var.vpc_cidr)) && var.vpc_cidr != "172.31.0.0/16"
    error_message = "vpc_cidr must be a valid CIDR and must not be the AWS default VPC range 172.31.0.0/16."
  }
}

variable "api_alb_internal" {
  type        = bool
  description = "Place the API ALB in private subnets (VPC-link only). Public internet reaches FastAPI through API Gateway + CloudFront, not the ALB."
  default     = true
}

variable "api_via_apigateway" {
  type        = bool
  description = "CloudFront /api* and /scim* origin is the HTTP API (VPC link to the ALB). Set false only while cutting over so the console keeps using the ALB origin."
  default     = true
}

variable "gmail_domain" {
  type        = string
  description = "Workspace primary domain (SEG_GMAIL_DOMAIN)."
  default     = "pdax.ph"
}

variable "enforce_mode" {
  type        = string
  description = "SEG_ENFORCE. Keep shadow until scoring is trusted."
  default     = "shadow"

  validation {
    condition     = contains(["shadow", "quarantine", "reject"], var.enforce_mode)
    error_message = "enforce_mode must be shadow, quarantine, or reject."
  }
}

variable "gmail_poll_seconds" {
  type        = number
  description = "Receiver poll interval."
  default     = 30
}

variable "content_provider" {
  type    = string
  default = "glm"
}

variable "intel_client" {
  type    = string
  default = "vt_abuseipdb"
}

variable "assign_public_ip" {
  type        = bool
  description = "Give Fargate tasks a public IP. Leave false — tasks run in private subnets behind NAT."
  default     = false
}

variable "api_cpu" {
  type        = number
  description = "API Fargate CPU units. 1024 = 1 vCPU (analyze + GLM)."
  default     = 1024
}

variable "api_memory" {
  type        = number
  description = "API Fargate memory (MiB). 2048 is the Fargate minimum at 1 vCPU."
  default     = 2048
}

variable "receiver_cpu" {
  type        = number
  description = "Receiver Fargate CPU units when running the all-in-one image."
  default     = 512
}

variable "receiver_memory" {
  type        = number
  description = "Receiver Fargate memory (MiB) for the all-in-one image."
  default     = 1024
}

variable "api_desired_count" {
  type        = number
  description = "API tasks. 2 covers both private subnets so a single-AZ blip does not take the console down."
  default     = 2

  validation {
    condition     = var.api_desired_count >= 1 && var.api_desired_count <= 8
    error_message = "api_desired_count must be between 1 and 8."
  }
}

variable "receiver_desired_count" {
  type        = number
  description = "All-in-one receiver tasks. 0 when split workers are deployed."
  default     = 0
}

variable "api_image_digest" {
  type        = string
  description = "sha256:… digest of the API image. Empty skips the API ECS service."
  default     = ""

  validation {
    condition     = var.api_image_digest == "" || startswith(var.api_image_digest, "sha256:")
    error_message = "api_image_digest must be empty or start with sha256:."
  }
}

variable "receiver_image_digest" {
  type        = string
  description = "sha256:… digest of the receiver image. Empty skips the receiver ECS service."
  default     = ""

  validation {
    condition     = var.receiver_image_digest == "" || startswith(var.receiver_image_digest, "sha256:")
    error_message = "receiver_image_digest must be empty or start with sha256:."
  }
}

variable "worker_image_digest" {
  type        = string
  description = "sha256:… digest of the worker image. Empty skips split worker ECS services."
  default     = ""

  validation {
    condition     = var.worker_image_digest == "" || startswith(var.worker_image_digest, "sha256:")
    error_message = "worker_image_digest must be empty or start with sha256:."
  }
}

variable "content_ai_desired_count" {
  type        = number
  description = "content_ai Fargate tasks. Each task runs SEG_CONTENT_AI_WORKERS in-process LLM consumers. Autoscaling is off in this account; scale with aws ecs update-service."
  default     = 8

  validation {
    condition     = var.content_ai_desired_count >= 1 && var.content_ai_desired_count <= 16
    error_message = "content_ai_desired_count must be between 1 and 16."
  }
}

variable "content_ai_max_count" {
  type        = number
  description = "Maximum content_ai tasks if autoscaling is enabled later."
  default     = 8

  validation {
    condition     = var.content_ai_max_count >= 1 && var.content_ai_max_count <= 16
    error_message = "content_ai_max_count must be between 1 and 16."
  }
}

variable "content_ai_scale_target" {
  type        = number
  description = "Target visible messages on the content_ai queue. Each task runs one LLM job."
  default     = 4
}

variable "static_min_count" {
  type    = number
  default = 4
}

variable "static_max_count" {
  type        = number
  description = "Maximum static-check tasks. VirusTotal quota is the usual brake, not CPU."
  default     = 8
}

variable "static_scale_target" {
  type        = number
  description = "Target visible messages on the static queue."
  default     = 8
}

variable "thread_ai_min_count" {
  type        = number
  description = "thread_ai Fargate tasks. Each task runs SEG_THREAD_AI_WORKERS in-process consumers."
  default     = 4
}

variable "thread_ai_max_count" {
  type    = number
  default = 8
}

variable "thread_ai_cpu" {
  type        = number
  description = "Fargate CPU for the thread_ai worker. 1024 (1 vCPU) fits four in-process consumers."
  default     = 1024
}

variable "thread_ai_memory" {
  type        = number
  description = "Fargate memory (MiB) for the thread_ai worker."
  default     = 2048
}

variable "thread_ai_scale_target" {
  type        = number
  description = "Target visible messages on the thread_ai queue."
  default     = 5
}

variable "sender_cpu" {
  type        = number
  description = "Fargate CPU for the combined sender-profile + sender-risk worker."
  default     = 2048
}

variable "sender_memory" {
  type        = number
  description = "Fargate memory (MiB) for the sender worker. 4096 is the Fargate minimum at 2 vCPU."
  default     = 4096
}

variable "sender_min_count" {
  type        = number
  description = "sender Fargate tasks. Each task runs SEG_PROFILE_WORKERS ingest threads plus SEG_SENDER_RISK_WORKERS LLM consumers."
  default     = 2

  validation {
    condition     = var.sender_min_count >= 1 && var.sender_min_count <= 8
    error_message = "sender_min_count must be between 1 and 8."
  }
}

variable "sender_max_count" {
  type        = number
  description = "Maximum sender tasks if autoscaling is enabled later."
  default     = 4

  validation {
    condition     = var.sender_max_count >= 1 && var.sender_max_count <= 8
    error_message = "sender_max_count must be between 1 and 8."
  }
}

variable "sender_scale_target" {
  type        = number
  description = "Target visible messages on the profile queue per sender task."
  default     = 20
}

variable "campaign_cpu" {
  type        = number
  description = "Fargate CPU for the campaign worker. 1024 (1 vCPU) fits four in-process ingest threads."
  default     = 1024
}

variable "campaign_memory" {
  type        = number
  description = "Fargate memory (MiB) for the campaign worker. 2048 is the Fargate minimum at 1 vCPU."
  default     = 2048
}

variable "campaign_min_count" {
  type        = number
  description = "campaign Fargate tasks. Keep 1 — recompute rewrites the campaigns table."
  default     = 1

  validation {
    condition     = var.campaign_min_count >= 1 && var.campaign_min_count <= 2
    error_message = "campaign_min_count must be 1 or 2."
  }
}

variable "campaign_max_count" {
  type        = number
  description = "Maximum campaign tasks. Keep 1 unless recompute is partitioned."
  default     = 1

  validation {
    condition     = var.campaign_max_count >= 1 && var.campaign_max_count <= 2
    error_message = "campaign_max_count must be 1 or 2."
  }
}

variable "campaign_scale_target" {
  type        = number
  description = "Target visible messages on the campaign queue per campaign task."
  default     = 40
}

variable "aurora_min_capacity" {
  type        = number
  description = "Aurora Serverless v2 minimum ACU."
  default     = 0.5
}

variable "aurora_max_capacity" {
  type        = number
  description = "Aurora Serverless v2 maximum ACU. Raise before adding content_ai tasks."
  default     = 2
}

variable "enable_worker_autoscaling" {
  type        = bool
  description = "SQS target tracking for static/content_ai/thread_ai. The sandbox SSO role cannot iam:CreateServiceLinkedRole or iam:PassRole to application-autoscaling; leave false until an admin grants one of those."
  default     = false
}

variable "content_ai_cpu" {
  type        = number
  description = "Fargate CPU for the content_ai worker. 2048 (2 vCPU) fits four in-process LLM consumers."
  default     = 2048
}

variable "content_ai_memory" {
  type        = number
  description = "Fargate memory (MiB) for the content_ai worker. 4096 is the Fargate minimum at 2 vCPU."
  default     = 4096
}

variable "static_cpu" {
  type        = number
  description = "Fargate CPU for the static worker. 2048 (2 vCPU) fits four in-process consumers."
  default     = 2048
}

variable "static_memory" {
  type        = number
  description = "Fargate memory (MiB) for the static worker. 4096 is the Fargate minimum at 2 vCPU."
  default     = 4096
}

variable "poll_cpu" {
  type    = number
  default = 512
}

variable "poll_memory" {
  type    = number
  default = 1024
}

variable "sync_console" {
  type        = bool
  description = "Upload web-console/dist to S3. Requires a local npm build."
  default     = false
}

variable "console_dist_path" {
  type        = string
  description = "Path to Vite output, relative to the infra/ directory."
  default     = "../web-console/dist"
}

variable "log_retention_days" {
  type        = number
  description = "CloudWatch Logs retention. Fixed at 90 days."
  default     = 90

  validation {
    condition     = var.log_retention_days == 90
    error_message = "log_retention_days must be 90."
  }
}

variable "waf_login_rate_limit" {
  type        = number
  description = "Requests per 5 minutes per IP to /api/auth/login before WAF blocks."
  default     = 100
}
