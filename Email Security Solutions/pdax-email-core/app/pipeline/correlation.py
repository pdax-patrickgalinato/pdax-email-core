"""Local correlation store — the standalone, no-external-dependency half of
Correlated Intelligence (TMES policy parity). Trend Micro's Correlated
Intelligence leans on a global cross-customer sensor network no in-house tool
can replicate; the practical substitute is correlating against PDAX's own
verdict history, so a repeat campaign that already fooled the deterministic
engine once gets flagged as "seen before" on the second attempt even without
any external threat-intel feed.

Deliberately weighted-only, never a hard override (see verdict.py) — a local
history hit means "PDAX's own pipeline flagged this before," a lower-
confidence signal than a real external intel hit (which stays a hard
override). Write path only ever persists SUSPICIOUS/MALICIOUS verdicts —
recording CLEAN mail's IOCs isn't useful signal and just bloats the store.

Fail-soft by design, same posture as every other enrichment hook in this
codebase: a locked/corrupt/missing-permissions SQLite file degrades the
correlation lookup/write to a no-op rather than raising and sinking the
pipeline.
"""
from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Optional

_DEFAULT_DB_PATH = Path(__file__).resolve().parents[2] / "data" / "verdict_history.sqlite3"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS verdict_history (
    ioc_value TEXT NOT NULL,
    ioc_type TEXT NOT NULL,
    verdict TEXT NOT NULL,
    message_id TEXT,
    seen_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_verdict_history_ioc ON verdict_history(ioc_value, ioc_type);
"""

# Only these two verdicts are worth remembering — see module docstring.
_RECORDABLE_VERDICTS = {"SUSPICIOUS", "MALICIOUS"}


class CorrelationStore:
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path) if db_path else _DEFAULT_DB_PATH

    def _connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path), timeout=5)
        conn.executescript(_SCHEMA)
        return conn

    def lookup(self, domains: list = None, ips: list = None, urls: list = None,
              hashes: list = None, senders: list = None) -> list:
        """Returns correlation_seen_before:<value>:<n> flags for any IOC that
        already has n>=1 prior SUSPICIOUS/MALICIOUS verdicts on record.
        Degrades to [] on any storage error — never raises."""
        candidates = []
        for value in (domains or []):
            candidates.append(("domain", value))
        for value in (ips or []):
            candidates.append(("ip", value))
        for value in (urls or []):
            candidates.append(("url", value))
        for value in (hashes or []):
            candidates.append(("hash", value))
        for value in (senders or []):
            candidates.append(("sender", value))
        if not candidates:
            return []

        try:
            conn = self._connect()
            try:
                flags = []
                for ioc_type, value in candidates:
                    row = conn.execute(
                        "SELECT COUNT(*) FROM verdict_history WHERE ioc_value = ? AND ioc_type = ?",
                        (value, ioc_type),
                    ).fetchone()
                    n = row[0] if row else 0
                    if n:
                        flags.append(f"correlation_seen_before:{value}:{n}")
                return flags
            finally:
                conn.close()
        except (sqlite3.Error, OSError):
            return []

    def record(self, verdict: str, message_id: str = "", domains: list = None,
              ips: list = None, urls: list = None, hashes: list = None,
              senders: list = None) -> bool:
        """Persists this email's IOCs tagged with its verdict, only for
        SUSPICIOUS/MALICIOUS. Returns whether anything was written (mainly
        useful for tests); a storage failure degrades silently to False."""
        if verdict not in _RECORDABLE_VERDICTS:
            return False
        rows = []
        now = time.time()
        for ioc_type, values in (
            ("domain", domains), ("ip", ips), ("url", urls),
            ("hash", hashes), ("sender", senders),
        ):
            for value in (values or []):
                if value:
                    rows.append((value, ioc_type, verdict, message_id, now))
        if not rows:
            return False

        try:
            conn = self._connect()
            try:
                conn.executemany(
                    "INSERT INTO verdict_history (ioc_value, ioc_type, verdict, message_id, seen_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    rows,
                )
                conn.commit()
                return True
            finally:
                conn.close()
        except (sqlite3.Error, OSError):
            return False


def get_default_store() -> CorrelationStore:
    return CorrelationStore()
