"""Shared pytest fixtures. Packages are importable via pyproject pythonpath
and `pip install -e .` — tests must not sys.path-hack."""
from __future__ import annotations

from pathlib import Path

import pytest

from backend.paths import REPO_ROOT, TEST_EML_DIR

# Meets server.auth_store complexity rules (upper, lower, digit, special).
TEST_PASSWORD = "Password123!"


@pytest.fixture(autouse=True)
def _offline_origin_ip_enrichment(monkeypatch):
    """Never spend a live Gemini Search or ip-api geo call during unit tests."""
    monkeypatch.setenv("SEG_ORIGIN_IP_SEARCH", "0")
    monkeypatch.setenv("SEG_ORIGIN_IP_GEO", "0")
    monkeypatch.setenv("SEG_PROFILE_WORKER", "0")
    monkeypatch.setenv("SEG_INCONCLUSIVE_RETRY", "0")
    monkeypatch.setenv("SEG_CAMPAIGN_WORKER", "0")
    monkeypatch.setenv("SEG_SENDER_RISK_WORKER", "0")


@pytest.fixture(autouse=True)
def _isolate_gmail_coverage(tmp_path, monkeypatch):
    """Do not write fan-out coverage into the developer's data/ directory."""
    from backend.stores import gmail_coverage
    monkeypatch.setattr(gmail_coverage, "_STORE_OVERRIDE", tmp_path / "gmail_coverage.json")


@pytest.fixture(autouse=True)
def _isolate_followup(tmp_path):
    from workers import followup
    followup.set_db_path(tmp_path / "followup.sqlite3")
    followup.reset()
    yield
    followup.reset()
    followup.set_db_path(None)


@pytest.fixture(autouse=True)
def _isolate_jobs(tmp_path):
    from workers import jobs
    jobs.set_db_path(tmp_path / "worker_jobs.sqlite3")
    jobs.reset()
    yield
    jobs.reset()
    jobs.set_db_path(None)


@pytest.fixture(autouse=True)
def _reset_worker_stop():
    import workers.runtime as runtime
    from workers import content_ai as cai
    runtime.stop.clear()
    runtime.set_process("unknown")
    cai._queued.clear()
    cai._inflight.clear()
    yield
    runtime.stop_workers()
    runtime.set_process("unknown")
    cai._queued.clear()
    cai._inflight.clear()
    from workers import sender_risk as sr
    with sr._offered_lock:
        sr._offered.clear()
        sr._offered_set.clear()


@pytest.fixture(autouse=True)
def _isolate_heartbeats(tmp_path, monkeypatch):
    import workers.runtime as runtime
    monkeypatch.setattr(runtime, "HEARTBEAT_DIR", tmp_path / "worker_heartbeats")


@pytest.fixture(autouse=True)
def _isolate_activity_log(tmp_path):
    from backend.api import activity_log
    orig = activity_log._DEFAULT_PATH
    activity_log._DEFAULT_PATH = tmp_path / "activity_audit.jsonl"
    yield
    activity_log._DEFAULT_PATH = orig


@pytest.fixture(autouse=True)
def _isolate_assessments(tmp_path):
    from backend.stores import assessments
    assessments.set_db_path(tmp_path / "assessments.sqlite3")
    assessments.reset()
    yield
    assessments.reset()
    assessments.set_db_path(None)


@pytest.fixture
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture
def samples_dir() -> Path:
    return TEST_EML_DIR


@pytest.fixture
def fixtures_dir() -> Path:
    return TEST_EML_DIR
