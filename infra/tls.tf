# Private CA + server cert for TLS inside the VPC.
# Public ACM cannot issue for *.elb.amazonaws.com, and this stack has no
# Route 53 name, so the ALB and Fargate tasks use an imported certificate.
# API Gateway's VPC link does not need to trust this CA (it connects by
# listener ARN). Tasks and the API→workers probe do, via SEG_TLS_CA.

resource "tls_private_key" "ca" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "ca" {
  private_key_pem       = tls_private_key.ca.private_key_pem
  is_ca_certificate     = true
  validity_period_hours = 87600
  allowed_uses = [
    "cert_signing",
    "crl_signing",
    "digital_signature",
  ]

  subject {
    common_name  = "${local.name} internal CA"
    organization = "SEGS"
  }
}

resource "tls_private_key" "internal" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_cert_request" "internal" {
  private_key_pem = tls_private_key.internal.private_key_pem

  subject {
    common_name  = "${local.name}.internal"
    organization = "SEGS"
  }

  dns_names = compact(concat(
    [
      aws_lb.api.dns_name,
      "localhost",
      "${local.name}.internal",
    ],
    [for lb in aws_lb.workers : lb.dns_name],
  ))

  ip_addresses = ["127.0.0.1"]
}

resource "tls_locally_signed_cert" "internal" {
  cert_request_pem   = tls_cert_request.internal.cert_request_pem
  ca_private_key_pem = tls_private_key.ca.private_key_pem
  ca_cert_pem        = tls_self_signed_cert.ca.cert_pem

  validity_period_hours = 87600
  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]
}

resource "aws_acm_certificate" "internal" {
  private_key       = tls_private_key.internal.private_key_pem
  certificate_body  = tls_locally_signed_cert.internal.cert_pem
  certificate_chain = tls_self_signed_cert.ca.cert_pem

  lifecycle {
    create_before_destroy = true
  }
}
