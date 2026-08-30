locals {
  waf_managed_groups = [
    {
      name     = "AWSManagedRulesAmazonIpReputationList"
      priority = 1
    },
    {
      name     = "AWSManagedRulesKnownBadInputsRuleSet"
      priority = 2
    },
    {
      name     = "AWSManagedRulesCommonRuleSet"
      priority = 3
    },
  ]

  # Analyze uploads EML/HTML that trip body size and XSS/SQLi body rules.
  waf_common_overrides = [
    "SizeRestrictions_BODY",
    "CrossSiteScripting_BODY",
    "SQLi_BODY",
  ]
}

resource "aws_wafv2_web_acl" "cloudfront" {
  provider = aws.us_east_1

  name  = "${local.name}-cloudfront"
  scope = "CLOUDFRONT"

  default_action {
    allow {}
  }

  dynamic "rule" {
    for_each = local.waf_managed_groups
    content {
      name     = rule.value.name
      priority = rule.value.priority

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          name        = rule.value.name
          vendor_name = "AWS"

          dynamic "rule_action_override" {
            for_each = rule.value.name == "AWSManagedRulesCommonRuleSet" ? local.waf_common_overrides : []
            content {
              name = rule_action_override.value
              action_to_use {
                count {}
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = replace(rule.value.name, "/[^A-Za-z0-9]/", "")
        sampled_requests_enabled   = true
      }
    }
  }

  rule {
    name     = "RateLimitLogin"
    priority = 10

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = var.waf_login_rate_limit
        aggregate_key_type = "IP"

        scope_down_statement {
          byte_match_statement {
            positional_constraint = "STARTS_WITH"
            search_string         = "/api/auth/"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "segsRateLogin"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.name}CloudFront"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl" "alb" {
  name  = "${local.name}-alb"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  dynamic "rule" {
    for_each = local.waf_managed_groups
    content {
      name     = rule.value.name
      priority = rule.value.priority

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          name        = rule.value.name
          vendor_name = "AWS"

          dynamic "rule_action_override" {
            for_each = rule.value.name == "AWSManagedRulesCommonRuleSet" ? local.waf_common_overrides : []
            content {
              name = rule_action_override.value
              action_to_use {
                count {}
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "alb${replace(rule.value.name, "/[^A-Za-z0-9]/", "")}"
        sampled_requests_enabled   = true
      }
    }
  }

  rule {
    name     = "RateLimitLogin"
    priority = 10

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = var.waf_login_rate_limit
        aggregate_key_type = "IP"

        scope_down_statement {
          byte_match_statement {
            positional_constraint = "STARTS_WITH"
            search_string         = "/api/auth/"
            field_to_match {
              uri_path {}
            }
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "albRateLogin"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.name}Alb"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = aws_lb.api.arn
  web_acl_arn  = aws_wafv2_web_acl.alb.arn
}
