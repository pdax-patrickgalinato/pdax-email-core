resource "aws_ecr_repository" "api" {
  name                 = "pdax/${var.name_prefix}-api"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = false

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }
}

resource "aws_ecr_repository" "worker" {
  name                 = "pdax/${var.name_prefix}-worker"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = false

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }
}

resource "aws_ecr_repository" "receiver" {
  name                 = "pdax/${var.name_prefix}-receiver"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = false

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }
}

resource "aws_ecr_lifecycle_policy" "api" {
  repository = aws_ecr_repository.api.name
  policy     = local.ecr_lifecycle
}

resource "aws_ecr_lifecycle_policy" "worker" {
  repository = aws_ecr_repository.worker.name
  policy     = local.ecr_lifecycle
}

resource "aws_ecr_lifecycle_policy" "receiver" {
  repository = aws_ecr_repository.receiver.name
  policy     = local.ecr_lifecycle
}

locals {
  ecr_lifecycle = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last 20 images"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 20
        }
        action = { type = "expire" }
      }
    ]
  })
}
