"""Repository-rooted paths.

`backend/paths.py` → parents[0]=backend, [1]=git root.
Raw mail lives under `email/spool` (override with `SEG_QUARANTINE_ROOT`).
`data/` is SQLite and other runtime state, not the spool.

Detection policy ships in `backend/policy/` (package data). Dashboard-writable
runtime YAML is the same tree so Fargate does not need a top-level `rules/` dir.
"""
from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = Path(__file__).resolve().parent

POLICY_DIR = BACKEND_DIR / "policy"
RULES_DETECTION = POLICY_DIR / "detection"
RULES_IDENTITY = POLICY_DIR / "identity"
RULES_RUNTIME = POLICY_DIR / "runtime"

# Synthetic + regression .eml files used by pytest / eval. Not production mail.
TEST_EML_DIR = BACKEND_DIR / "tests" / "fixtures" / "eml"

DATA_DIR = REPO_ROOT / "data"
SPOOL_DIR = REPO_ROOT / "email" / "spool"
WEB_CONSOLE_DIST = REPO_ROOT / "web-console" / "dist"
CREDENTIALS_PATH = REPO_ROOT / "credentials.json"
