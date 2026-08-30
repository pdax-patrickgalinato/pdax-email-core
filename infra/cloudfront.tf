resource "aws_cloudfront_function" "spa_fallback" {
  name    = "${local.name}-spa-fallback"
  runtime = "cloudfront-js-2.0"
  publish = true
  code    = <<-EOF
    function handler(event) {
      var request = event.request;
      var uri = request.uri;
      if (uri.indexOf('.') !== -1) {
        return request;
      }
      request.uri = '/index.html';
      return request;
    }
  EOF
}

resource "aws_cloudfront_response_headers_policy" "console" {
  name = "${local.name}-security"

  security_headers_config {
    content_type_options {
      override = true
    }
    frame_options {
      frame_option = "DENY"
      override     = true
    }
    referrer_policy {
      referrer_policy = "strict-origin-when-cross-origin"
      override        = true
    }
    strict_transport_security {
      access_control_max_age_sec = 31536000
      include_subdomains         = true
      override                   = true
    }
    xss_protection {
      mode_block = true
      protection = true
      override   = true
    }
    content_security_policy {
      content_security_policy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob: https: http:; media-src 'self' data: blob: https:; connect-src 'self'; frame-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self';"
      override                = true
    }
  }
}

resource "aws_cloudfront_distribution" "console" {
  enabled             = true
  is_ipv6_enabled     = true
  comment             = var.api_via_apigateway ? "SEGS web console + /api and /scim via API Gateway" : "SEGS web console + /api origin"
  default_root_object = "index.html"
  price_class         = "PriceClass_200"
  web_acl_id          = aws_wafv2_web_acl.cloudfront.arn
  wait_for_deployment = true

  origin {
    domain_name              = aws_s3_bucket.console.bucket_regional_domain_name
    origin_id                = "s3-console"
    origin_access_control_id = aws_cloudfront_origin_access_control.console.id
  }

  origin {
    domain_name = "${aws_apigatewayv2_api.http.id}.execute-api.${var.aws_region}.amazonaws.com"
    origin_id   = "apigw-api"

    custom_origin_config {
      http_port                = 80
      https_port               = 443
      origin_protocol_policy   = "https-only"
      origin_ssl_protocols     = ["TLSv1.2"]
      origin_read_timeout      = 60
      origin_keepalive_timeout = 5
    }
  }

  dynamic "origin" {
    for_each = var.api_via_apigateway ? [] : [1]
    content {
      domain_name = aws_lb.api.dns_name
      origin_id   = "alb-api"

      custom_origin_config {
        http_port                = 80
        https_port               = 443
        origin_protocol_policy   = "https-only"
        origin_ssl_protocols     = ["TLSv1.2"]
        origin_read_timeout      = 60
        origin_keepalive_timeout = 5
      }
    }
  }

  default_cache_behavior {
    target_origin_id       = "s3-console"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]
    compress               = true

    cache_policy_id            = local.cloudfront_cache_optimized
    origin_request_policy_id   = local.cloudfront_origin_s3_cors
    response_headers_policy_id = aws_cloudfront_response_headers_policy.console.id

    function_association {
      event_type   = "viewer-request"
      function_arn = aws_cloudfront_function.spa_fallback.arn
    }
  }

  ordered_cache_behavior {
    path_pattern           = "/api*"
    target_origin_id       = local.api_origin_id
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods         = ["GET", "HEAD"]
    compress               = true

    cache_policy_id            = local.cloudfront_cache_disabled
    origin_request_policy_id   = local.cloudfront_origin_all_viewer
    response_headers_policy_id = aws_cloudfront_response_headers_policy.console.id
  }

  ordered_cache_behavior {
    path_pattern           = "/scim*"
    target_origin_id       = local.api_origin_id
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods         = ["GET", "HEAD"]
    compress               = true

    cache_policy_id            = local.cloudfront_cache_disabled
    origin_request_policy_id   = local.cloudfront_origin_all_viewer
    response_headers_policy_id = aws_cloudfront_response_headers_policy.console.id
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}
