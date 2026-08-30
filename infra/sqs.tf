locals {
  queues = {
    static = {
      visibility = 420
    }
    content_ai = {
      visibility = 420
    }
    thread_ai = {
      visibility = 90
    }
    campaign = {
      visibility = 180
    }
    profile = {
      visibility = 120
    }
  }
}

resource "aws_sqs_queue" "dlq" {
  for_each = local.queues

  name                              = "${local.name}-${replace(each.key, "_", "-")}-dlq"
  kms_master_key_id                 = aws_kms_key.this.arn
  kms_data_key_reuse_period_seconds = 300
  message_retention_seconds         = 1209600
}

resource "aws_sqs_queue" "this" {
  for_each = local.queues

  name                              = "${local.name}-${replace(each.key, "_", "-")}"
  visibility_timeout_seconds        = each.value.visibility
  receive_wait_time_seconds         = 20
  kms_master_key_id                 = aws_kms_key.this.arn
  kms_data_key_reuse_period_seconds = 300
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dlq[each.key].arn
    maxReceiveCount     = 8
  })
}
