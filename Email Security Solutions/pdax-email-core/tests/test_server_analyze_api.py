"""Unit tests for POST /api/analyze/eml — mocked agent + heuristic pipeline.

Never hits live GLM. Uses an isolated auth store like the other server tests.

Run: python3 tests/test_server_analyze_api.py
"""
from __future__ import annotations

import io
import os
import sys
import tempfile
from pathlib import Path
from unittest import mock

os.environ["SEG_DASHBOARD_LLM"] = "0"
os.environ["SEG_DASHBOARD_DEEP"] = "0"

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from starlette.testclient import TestClient

from server.auth_store import AuthStore

_MIN_EML = (
    b"From: sender@example.com\r\n"
    b"To: victim@example.com\r\n"
    b"Subject: Test message\r\n"
    b"Message-ID: <test@example.com>\r\n"
    b"\r\n"
    b"Hello world.\r\n"
)


def _client_as(role: str) -> TestClient:
    from fastapi import FastAPI
    from server.routers import analyze as analyze_module
    import server.deps as deps_module

    store = AuthStore(db_path=Path(tempfile.mkstemp(suffix=".sqlite3")[1]))
    deps_module._store = store
    user = store.create_user("testuser", "password123", role)

    app = FastAPI()
    app.include_router(analyze_module.router)
    client = TestClient(app)
    token = store.create_session(user.id)
    client.cookies.set("seg_session", token)
    return client


def test_viewer_forbidden():
    client = _client_as("viewer")
    r = client.post(
        "/api/analyze/eml",
        files={"file": ("x.eml", io.BytesIO(_MIN_EML), "message/rfc822")},
    )
    assert r.status_code == 403


def test_unauthenticated_rejected():
    from fastapi import FastAPI
    from server.routers import analyze as analyze_module
    import server.deps as deps_module

    store = AuthStore(db_path=Path(tempfile.mkstemp(suffix=".sqlite3")[1]))
    deps_module._store = store
    app = FastAPI()
    app.include_router(analyze_module.router)
    client = TestClient(app)
    r = client.post(
        "/api/analyze/eml",
        files={"file": ("x.eml", io.BytesIO(_MIN_EML), "message/rfc822")},
    )
    assert r.status_code in (401, 403)


def test_rejects_non_eml_extension():
    client = _client_as("analyst")
    r = client.post(
        "/api/analyze/eml",
        files={"file": ("note.txt", io.BytesIO(b"not an email"), "text/plain")},
    )
    assert r.status_code == 400
    assert "eml" in r.json()["detail"].lower()


def test_rejects_oversized_file():
    client = _client_as("admin")
    huge = b"From: a@b.com\r\n\r\n" + (b"x" * (15 * 1024 * 1024 + 1))
    r = client.post(
        "/api/analyze/eml",
        files={"file": ("big.eml", io.BytesIO(huge), "message/rfc822")},
    )
    assert r.status_code == 413


def test_missing_credentials_returns_503():
    client = _client_as("analyst")
    with mock.patch("eml_analysis_agent.resolve_glm_credentials_path",
                    return_value=Path("/tmp/definitely-missing-segs-creds.json")):
        r = client.post(
            "/api/analyze/eml",
            files={"file": ("x.eml", io.BytesIO(_MIN_EML), "message/rfc822")},
        )
    assert r.status_code == 503


def test_success_shape_with_mocked_agent():
    client = _client_as("admin")
    fake_deep = {
        "filename": "x.eml",
        "analysis": {
            "content_analysis": {"summary": "Benign test mail."},
            "threat_assessment": {
                "risk_level": "LOW",
                "risk_score": 10,
                "indicators": ["none"],
            },
        },
        "markdown": "# Email Analysis Report — x.eml\n\nOK\n",
        "playbook": None,
        "consistency_warning": None,
        "model": "mock-model",
        "elapsed_ms": 12,
    }
    with mock.patch("eml_analysis_agent.resolve_glm_credentials_path",
                    return_value=Path(__file__)), \
         mock.patch("eml_analysis_agent.analyze_eml_bytes", return_value=fake_deep):
        # Path(__file__) exists — satisfies the is_file() gate before analyze_eml_bytes
        r = client.post(
            "/api/analyze/eml",
            files={"file": ("x.eml", io.BytesIO(_MIN_EML), "message/rfc822")},
        )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["filename"] == "x.eml"
    assert body["markdown"].startswith("# Email Analysis Report")
    assert body["analysis"]["threat_assessment"]["risk_level"] == "LOW"
    assert body["pipeline"]["verdict"] in ("CLEAN", "LOW", "SUSPICIOUS", "MALICIOUS")
    assert "disposition" in body["pipeline"]
    assert "elapsed_ms" in body
    assert body["model"] == "mock-model"


if __name__ == "__main__":
    tests = [
        test_viewer_forbidden,
        test_unauthenticated_rejected,
        test_rejects_non_eml_extension,
        test_rejects_oversized_file,
        test_missing_credentials_returns_503,
        test_success_shape_with_mocked_agent,
    ]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"OK  {t.__name__}")
        except Exception as e:
            failed += 1
            print(f"FAIL {t.__name__}: {type(e).__name__}: {e}")
    raise SystemExit(1 if failed else 0)
