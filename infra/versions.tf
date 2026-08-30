terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }

  # First apply can use local state. Then:
  #   terraform init -migrate-state
  # with a bucket/table you create once outside this stack.
  #
  # backend "s3" {
  #   bucket         = "pdax-segs-tfstate"
  #   key            = "prod/terraform.tfstate"
  #   region         = "ap-southeast-1"
  #   dynamodb_table = "pdax-segs-tflock"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = local.tags
  }
}

# CloudFront WAFv2 ACLs must live in us-east-1.
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"

  default_tags {
    tags = local.tags
  }
}
