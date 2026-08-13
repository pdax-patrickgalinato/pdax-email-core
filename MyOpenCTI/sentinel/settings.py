"""Persisted UI settings (.sentinel_settings.json at project root)."""
from __future__ import annotations

import json
import os
from typing import Dict, Tuple

import streamlit as st

from sentinel.config import (
    CATEGORY_ORDER, DEFAULT_KEYWORDS, DEFAULT_TECH_STACK, DEFAULT_TIMEOUT,
    IND_VASP, WAZUH_DEFAULT_LIST, WAZUH_DEFAULT_PORT,
)
from sentinel.feeds_matrix import FEED_MATRIX
from sentinel.llm import _apply_provider_preset

# Persist next to app.py (project root), not inside the package folder.
_APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SETTINGS_PATH = os.path.join(_APP_DIR, ".sentinel_settings.json")

PERSIST_DEFAULTS: Dict[str, object] = {
    "industry": IND_VASP,
    "tech_blob": DEFAULT_TECH_STACK,
    "kw_blob": DEFAULT_KEYWORDS,
    "w_tech": 12, "w_keyword": 6, "w_exploit": 14, "w_cve": 5, "w_kev": 18,
    "w_actor": 10, "w_malware": 6, "w_ransomware": 8, "w_recency": 8,
    "w_industry_step": 0.12, "w_industry_cap": 1.7, "w_sector_source": 10,
    "w_authority_scale": 1.0, "curve_midpoint": 60, "w_corroboration": 8,
    "max_items": 25, "max_age_days": 14, "timeout": DEFAULT_TIMEOUT,
    "ttl_minutes": 15, "force_refresh": False, "refresh_kev": False,
    "deep_scan_top": 8,
    # LLM enrichment — Ollama local by default (cloud consoles often captcha/geo blocked).
    "llm_enabled": False,
    "llm_provider": "ollama",
    "llm_base_url": "http://127.0.0.1:11434/v1",
    "llm_api_key": "",
    "llm_model": "llama3.2",
    "llm_credentials_path": "",
    "llm_project_id": "",
    "llm_location": "global",
    "llm_max_tokens": 4000,
    "llm_enrich_top": 0,
    # Wazuh SIEM connection (stored locally next to the app — never leaves this machine
    # unless you click Push IOCs).
    "wazuh_url": f"https://127.0.0.1:{WAZUH_DEFAULT_PORT}",
    "wazuh_user": "wazuh-wui",
    "wazuh_password": "",
    "wazuh_verify_ssl": False,
    "wazuh_list_name": WAZUH_DEFAULT_LIST,
    "wazuh_restart": True,
}

# Slider bounds so a persisted value that drifts out of range can't crash a widget.
_SETTING_BOUNDS: Dict[str, Tuple[float, float]] = {
    "w_tech": (2, 25), "w_keyword": (1, 15), "w_exploit": (2, 25), "w_cve": (1, 15),
    "w_kev": (5, 30), "w_actor": (2, 20), "w_malware": (1, 15), "w_ransomware": (2, 20),
    "w_recency": (0, 20), "w_industry_step": (0.0, 0.30), "w_industry_cap": (1.0, 2.5),
    "w_sector_source": (0, 25), "w_authority_scale": (0.0, 2.0), "curve_midpoint": (20, 150),
    "w_corroboration": (0, 20), "max_items": (5, 60), "max_age_days": (1, 60),
    "timeout": (5, 45), "ttl_minutes": (0, 120), "deep_scan_top": (0, 25),
    "llm_max_tokens": (800, 16000), "llm_enrich_top": (0, 15),
}

_INT_SETTINGS = {
    "w_tech", "w_keyword", "w_exploit", "w_cve", "w_kev", "w_actor", "w_malware",
    "w_ransomware", "w_recency", "w_sector_source", "curve_midpoint", "w_corroboration",
    "max_items", "max_age_days", "timeout", "ttl_minutes", "deep_scan_top",
    "llm_max_tokens", "llm_enrich_top",
}


def _coerce_setting(key: str, value):
    """Keep types/ranges sane when loading user-edited or older settings files."""
    try:
        if key in _INT_SETTINGS:
            value = int(round(float(value)))
        elif key in _SETTING_BOUNDS:
            value = float(value)
    except (TypeError, ValueError):
        return PERSIST_DEFAULTS.get(key)
    if key in _SETTING_BOUNDS:
        lo, hi = _SETTING_BOUNDS[key]
        value = max(lo, min(hi, value))
    return value


def load_persisted_settings() -> dict:
    try:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:  # noqa: BLE001 — a missing/corrupt file just means "use defaults"
        return {}


def _state_get(state, key, default=None):
    """Read from Streamlit session_state-like mappings safely."""
    try:
        if key in state:
            return state[key]
    except Exception:  # noqa: BLE001
        pass
    try:
        return state.get(key, default)
    except Exception:  # noqa: BLE001
        return default


def save_persisted_settings(state=None) -> bool:
    """Write profile/tuning/feed toggles to disk. Returns True when a write happened."""
    state = st.session_state if state is None else state
    # Start from whatever is already on disk so a partial session can't wipe keys.
    data = load_persisted_settings()
    for k, default in PERSIST_DEFAULTS.items():
        if k in state:
            data[k] = state[k]
        elif k not in data:
            data[k] = default
    for cat in CATEGORY_ORDER:
        key = f"cat_{cat}"
        if key in state:
            data[key] = bool(state[key])
    for f in FEED_MATRIX:
        key = f"feed_{f.url}"
        if key in state:
            data[key] = bool(state[key])
    payload = json.dumps(data, indent=2, sort_keys=True)
    # Only touch disk when something actually changed — avoids a write on every rerun.
    if st.session_state.get("_settings_last_written") == payload:
        return False
    try:
        os.makedirs(os.path.dirname(SETTINGS_PATH) or ".", exist_ok=True)
        tmp_path = SETTINGS_PATH + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, SETTINGS_PATH)
        st.session_state["_settings_last_written"] = payload
        st.session_state["_settings_saved_at"] = datetime.now(PH_TZ)
        return True
    except Exception:  # noqa: BLE001 — read-only FS shouldn't break the app
        try:
            if os.path.exists(SETTINGS_PATH + ".tmp"):
                os.remove(SETTINGS_PATH + ".tmp")
        except OSError:
            pass
        return False


def _on_settings_change() -> None:
    """Widget callback — flush tech stack / tuning to disk as soon as Streamlit commits it."""
    save_persisted_settings(st.session_state)


def _on_llm_provider_change() -> None:
    """When the consumer AI provider changes, apply URL/model defaults and persist."""
    _apply_provider_preset(st.session_state.get("llm_provider") or "ollama")
    save_persisted_settings(st.session_state)


def init_persisted_state() -> None:
    """Hydrate session_state from disk before any widgets bind to the keys.

    Force-assign on first load (not setdefault) so a blank Streamlit widget default cannot
    shadow the saved tech stack. Also repair wiped free-text fields after a browser refresh
    reconnect where Streamlit keeps `_settings_loaded` but clears widget values.
    """
    persisted = load_persisted_settings()
    first_load = not st.session_state.get("_settings_loaded")

    for k, default in PERSIST_DEFAULTS.items():
        raw = persisted.get(k, default)
        val = _coerce_setting(k, raw) if k in _SETTING_BOUNDS else raw
        current = _state_get(st.session_state, k, None)
        if first_load or current is None:
            st.session_state[k] = val
        elif k in {"tech_blob", "kw_blob"} and (current == "" or current is None) and val:
            # Browser refresh can reconnect the session with empty text widgets while
            # leaving our loaded flag set — restore the last saved profile text.
            st.session_state[k] = val

    for cat in CATEGORY_ORDER:
        key = f"cat_{cat}"
        if first_load or key not in st.session_state:
            st.session_state[key] = bool(persisted.get(key, True))
    for f in FEED_MATRIX:
        key = f"feed_{f.url}"
        if first_load or key not in st.session_state:
            st.session_state[key] = bool(persisted.get(key, True))

    st.session_state["_settings_loaded"] = True
    # Remember the on-disk tech stack so we can detect successful restores in the UI.
    st.session_state["_settings_path"] = SETTINGS_PATH

    # Nudge cloud defaults that often fail (Gemini geo, OpenAI billing, Groq captcha)
    # toward local Ollama when enrichment was never really configured.
    if first_load:
        prov = (st.session_state.get("llm_provider") or "").strip().lower()
        unused = (
            not st.session_state.get("llm_enabled")
            and not (st.session_state.get("llm_api_key") or "").strip()
        )
        if unused and prov in {
            "gemini", "openai", "openai_compatible", "groq",
        }:
            st.session_state["llm_provider"] = "ollama"
            _apply_provider_preset("ollama")


def reset_persisted_settings() -> None:
    try:
        os.remove(SETTINGS_PATH)
    except OSError:
        pass
    for k in list(st.session_state.keys()):
        if (k in PERSIST_DEFAULTS or k.startswith("cat_") or k.startswith("feed_")
                or k in {"_settings_loaded", "_settings_last_written", "_settings_saved_at",
                         "_settings_path"}):
            del st.session_state[k]

