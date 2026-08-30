"""OpenAPI contract stays in sync with FastAPI routes and API Gateway body."""
from __future__ import annotations

from backend.api.openapi import (
    APIGW_SPEC,
    DOCS_SPEC,
    _dump,
    build_apigw_spec,
    build_spec,
    operation_keys,
)


def test_openapi_covers_api_and_scim_not_spa():
    spec = build_spec()
    paths = spec["paths"]
    assert "/api/health" in paths
    assert "/api/feed" in paths
    assert "/api/campaigns" in paths
    assert "/scim/v2/Users" in paths
    assert "/{full_path}" not in paths
    assert "/" not in paths
    assert spec["openapi"].startswith("3.0")
    assert "bearerAuth" in spec["components"]["securitySchemes"]
    assert "cookieAuth" in spec["components"]["securitySchemes"]
    keys = operation_keys(spec)
    assert ("/api/health", "get") in keys
    assert ("/api/feed/search", "post") in keys
    assert ("/api/auth/login", "post") in keys
    assert ("/api/org/context/{note_id}", "patch") in keys
    assert paths["/api/health"]["get"]["security"] == []
    assert paths["/api/feed"]["get"]["security"]


def test_apigw_spec_attaches_vpc_link_integration():
    spec = build_apigw_spec()
    alb = spec["components"]["x-amazon-apigateway-integrations"]["alb"]
    assert alb["type"] == "HTTP_PROXY"
    assert alb["connectionType"] == "VPC_LINK"
    assert alb["connectionId"] == "${vpc_link_id}"
    assert alb["uri"] == "${alb_listener_arn}"
    feed = spec["paths"]["/api/feed"]["get"]
    assert feed["x-amazon-apigateway-integration"]["$ref"].endswith("/alb")
    assert "head" in spec["paths"]["/api/feed"]


def test_checked_in_specs_match_fastapi(tmp_path):
    canonical = build_spec()
    apigw = build_apigw_spec(canonical)
    assert DOCS_SPEC.is_file(), "missing docs/openapi.yaml — run python -m backend.api.openapi"
    assert APIGW_SPEC.is_file(), "missing infra/openapi.yaml — run python -m backend.api.openapi"
    assert DOCS_SPEC.read_text(encoding="utf-8") == _dump(canonical)
    assert APIGW_SPEC.read_text(encoding="utf-8") == _dump(apigw)
    assert "${vpc_link_id}" in APIGW_SPEC.read_text(encoding="utf-8")
    assert "${alb_listener_arn}" in APIGW_SPEC.read_text(encoding="utf-8")
