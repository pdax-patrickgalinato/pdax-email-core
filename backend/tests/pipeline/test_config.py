"""Unit tests for app.config.Settings — env mapping without printing values."""
from __future__ import annotations

import os

from backend.config import Settings, get_settings


def _clear_seg_env(monkeypatch):
    for key in list(os.environ):
        if key.startswith("SEG") or key in (
            "AWS_REGION", "GEMINI_API_KEY", "GOOGLE_APPLICATION_CREDENTIALS",
        ):
            monkeypatch.delenv(key, raising=False)


def test_defaults_are_offline_safe(monkeypatch):
    _clear_seg_env(monkeypatch)
    s = Settings()
    assert s.enforce == "shadow"
    assert s.content_provider == "heuristic"
    assert s.intel_client == "local"
    assert s.landing_fetch is False
    assert s.rdap_lookup is False
    assert s.origin_ip_search is True
    assert s.origin_ip_geo is True
    assert s.llm_triage is False
    assert s.cookie_secure is False
    assert s.serve_spa is True
    assert s.dashboard_llm is True
    assert s.dashboard_deep is True
    assert s.profile_worker is True
    assert s.inconclusive_retry is True
    assert s.campaign_worker is True
    assert s.campaign_workers == 4
    assert s.sender_risk_worker is True
    assert s.sender_risk_batch == 5
    assert s.static_workers == 2
    assert s.content_ai_workers == 4
    assert s.profile_workers == 4
    assert s.gmail_domain == "pdax.ph"
    assert s.sender_risk_workers == 2
    assert s.intel_workers == 1
    assert s.job_lease_seconds == 360
    assert s.job_max_attempts == 8
    assert s.inline_workers is True


def test_opt_in_flags_from_env(monkeypatch):
    monkeypatch.setenv("SEG_LANDING_FETCH", "1")
    monkeypatch.setenv("SEG_RDAP_LOOKUP", "yes")
    monkeypatch.setenv("SEG_LLM_TRIAGE", "true")
    monkeypatch.setenv("SEG_ORIGIN_IP_SEARCH", "0")
    monkeypatch.setenv("SEG_ORIGIN_IP_GEO", "0")
    s = get_settings()
    assert s.landing_fetch is True
    assert s.rdap_lookup is True
    assert s.llm_triage is True
    assert s.origin_ip_search is False
    assert s.origin_ip_geo is False


def test_dashboard_flags_can_be_disabled(monkeypatch):
    monkeypatch.setenv("SEG_DASHBOARD_LLM", "0")
    monkeypatch.setenv("SEG_DASHBOARD_DEEP", "off")
    s = get_settings()
    assert s.dashboard_llm is False
    assert s.dashboard_deep is False


def test_enforce_reads_current_env(monkeypatch):
    monkeypatch.setenv("SEG_ENFORCE", "quarantine")
    assert get_settings().enforce == "quarantine"
    monkeypatch.setenv("SEG_ENFORCE", "shadow")
    assert get_settings().enforce == "shadow"


def test_gmail_poll_interval_default(monkeypatch):
    _clear_seg_env(monkeypatch)
    assert Settings().gmail_poll_seconds == 30
    monkeypatch.setenv("SEG_GMAIL_POLL_SECONDS", "15")
    assert get_settings().gmail_poll_seconds == 15


def test_receiver_health_url_default(monkeypatch):
    _clear_seg_env(monkeypatch)
    assert Settings().receiver_health_url == ""
    monkeypatch.setenv("SEG_RECEIVER_HEALTH_URL", "http://receiver:8766/health")
    assert get_settings().receiver_health_url == "http://receiver:8766/health"


def test_worker_health_base_url_default(monkeypatch):
    _clear_seg_env(monkeypatch)
    assert Settings().worker_health_base_url == ""
    assert Settings().worker_health_port == 8766
    monkeypatch.setenv("SEG_WORKER_HEALTH_BASE_URL", "http://workers.internal")
    monkeypatch.setenv("SEG_WORKER_HEALTH_PORT", "9876")
    assert get_settings().worker_health_base_url == "http://workers.internal"
    assert get_settings().worker_health_port == 9876


def test_llm_assess_timeout_default(monkeypatch):
    _clear_seg_env(monkeypatch)
    assert Settings().llm_assess_timeout_seconds == 120
    monkeypatch.setenv("SEG_LLM_ASSESS_TIMEOUT_SECONDS", "90")
    assert get_settings().llm_assess_timeout_seconds == 90


def test_inconclusive_retry_drain_defaults(monkeypatch):
    _clear_seg_env(monkeypatch)
    s = Settings()
    assert s.inconclusive_retry_seconds == 30
    assert s.inconclusive_retry_batch == 25
    monkeypatch.setenv("SEG_INCONCLUSIVE_RETRY_SECONDS", "45")
    monkeypatch.setenv("SEG_INCONCLUSIVE_RETRY_BATCH", "10")
    s2 = get_settings()
    assert s2.inconclusive_retry_seconds == 45
    assert s2.inconclusive_retry_batch == 10


def test_llm_model_timeout_default(monkeypatch):
    _clear_seg_env(monkeypatch)
    assert Settings().llm_model_timeout_seconds == 25
    monkeypatch.setenv("SEG_LLM_MODEL_TIMEOUT_SECONDS", "30")
    assert get_settings().llm_model_timeout_seconds == 30


def test_model_timeout_is_capped_below_attempt_budget(monkeypatch):
    from backend.stores import ai_assess
    _clear_seg_env(monkeypatch)
    monkeypatch.setenv("SEG_LLM_ASSESS_TIMEOUT_SECONDS", "120")
    monkeypatch.setenv("SEG_LLM_MODEL_TIMEOUT_SECONDS", "120")
    assert ai_assess.model_timeout_seconds() == 100.0


def test_serve_spa_can_be_disabled(monkeypatch):
    monkeypatch.setenv("SEG_SERVE_SPA", "0")
    assert get_settings().serve_spa is False


def test_unknown_env_vars_are_ignored(monkeypatch):
    monkeypatch.setenv("SEG_NOT_A_REAL_SETTING", "x")
    get_settings()  # must not raise

