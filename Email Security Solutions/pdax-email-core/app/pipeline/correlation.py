"""Behavioral correlation store — detects attacker campaign patterns across
email traffic over a 6-month rolling window.

Three detection rules:
  1. IP-Sender drift (SUSPICIOUS): the same sender address comes from multiple
     different originating IPs, OR a single originating IP is used by ≥5
     different sender addresses (shared attack platform).
  2. IP-Shortener abuse (SUSPICIOUS): an originating IP sends emails containing
     link-shortener URLs, even across different sender addresses.
  3. Cross-sender shortener sharing (MALICIOUS): different sender addresses use
     the same link shortener domain — strongest indicator of a coordinated
     campaign.

Behavioral results are REFERENCE ONLY — they do not contribute to the SEGS
composite score or verdict. They surface in the Analyze tab's Behavioral
Correlation report panel for analyst review.

Observations are recorded for ALL emails (not only flagged ones) so behavioral
baselines reflect the full mail flow. Each record stores the final verdict so
the UI can filter to "prior flagged emails" specifically.

Fail-soft by design — all storage errors degrade to silent no-ops.
"""
from __future__ import annotations

import logging
import sqlite3
import time
from pathlib import Path

_log = logging.getLogger(__name__)

_DEFAULT_DB_PATH = Path(__file__).resolve().parents[2] / "data" / "behavior_history.sqlite3"

# 6-month rolling window in seconds.
_WINDOW = 180 * 86400

# Minimum distinct-senders count before an IP is considered a shared platform.
_MANY_SENDERS_THRESHOLD = 5

# Max prior-email records returned per finding.
_MAX_EMAIL_RECORDS = 10

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sender_ip_log (
    sender TEXT NOT NULL,
    ip TEXT NOT NULL,
    verdict TEXT DEFAULT '',
    message_id TEXT,
    seen_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sil_sender ON sender_ip_log(sender);
CREATE INDEX IF NOT EXISTS idx_sil_ip ON sender_ip_log(ip);

CREATE TABLE IF NOT EXISTS ip_shortener_log (
    ip TEXT NOT NULL,
    sender TEXT NOT NULL,
    shortener_domain TEXT NOT NULL,
    verdict TEXT DEFAULT '',
    message_id TEXT,
    seen_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_isl_ip ON ip_shortener_log(ip);
CREATE INDEX IF NOT EXISTS idx_isl_shortener ON ip_shortener_log(shortener_domain);

CREATE TABLE IF NOT EXISTS sender_shortener_log (
    sender TEXT NOT NULL,
    shortener_domain TEXT NOT NULL,
    verdict TEXT DEFAULT '',
    message_id TEXT,
    seen_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ssl_sender ON sender_shortener_log(sender);
CREATE INDEX IF NOT EXISTS idx_ssl_shortener ON sender_shortener_log(shortener_domain);
"""

_FLAGGED = ("SUSPICIOUS", "MALICIOUS")


class BehavioralCorrelationStore:
    def __init__(self, db_path=None):
        self.db_path = Path(db_path) if db_path else _DEFAULT_DB_PATH

    def _connect(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path), timeout=5)
        conn.executescript(_SCHEMA)
        # Migration: add verdict column to tables created before this column existed.
        for table in ("sender_ip_log", "ip_shortener_log", "sender_shortener_log"):
            try:
                conn.execute(
                    f"ALTER TABLE {table} ADD COLUMN verdict TEXT DEFAULT ''")
                conn.commit()
            except sqlite3.OperationalError:
                pass  # column already present
        return conn

    def record_observation(
        self,
        sender,            # str: pe.from_addr, normalized to lowercase
        originating_ips,   # list[str]: pe.originating_ips()
        shortener_domains, # list[str]: from url stage facts["shortener_domains"]
        message_id="",
        verdict="",        # final pipeline verdict (CLEAN/LOW/SUSPICIOUS/MALICIOUS)
    ):
        """Record sender-IP and shortener associations for ALL emails."""
        sender = (sender or "").lower().strip()
        originating_ips = [ip for ip in (originating_ips or []) if ip]
        shortener_domains = [d for d in (shortener_domains or []) if d]
        if not sender and not originating_ips:
            return
        now = time.time()
        try:
            conn = self._connect()
            try:
                if sender and originating_ips:
                    conn.executemany(
                        "INSERT INTO sender_ip_log "
                        "(sender, ip, verdict, message_id, seen_at) VALUES (?,?,?,?,?)",
                        [(sender, ip, verdict, message_id, now)
                         for ip in originating_ips],
                    )
                if originating_ips and shortener_domains:
                    conn.executemany(
                        "INSERT INTO ip_shortener_log "
                        "(ip, sender, shortener_domain, verdict, message_id, seen_at) "
                        "VALUES (?,?,?,?,?,?)",
                        [
                            (ip, sender, domain, verdict, message_id, now)
                            for ip in originating_ips
                            for domain in shortener_domains
                        ],
                    )
                if sender and shortener_domains:
                    conn.executemany(
                        "INSERT INTO sender_shortener_log "
                        "(sender, shortener_domain, verdict, message_id, seen_at) "
                        "VALUES (?,?,?,?,?)",
                        [(sender, domain, verdict, message_id, now)
                         for domain in shortener_domains],
                    )
                conn.commit()
            finally:
                conn.close()
        except (sqlite3.Error, OSError) as exc:
            _log.warning("behavioral_store record_observation failed: %s", exc)

    def behavioral_details(
        self,
        sender,            # str
        originating_ips,   # list[str]
        shortener_domains, # list[str]
    ):
        """Return a list of finding dicts for triggered rules.

        Each dict: {rule, ioc_value, behavioral_count, flagged_count, emails}
        where emails is a list of {sender, message_id, seen_at, verdict} for
        prior SUSPICIOUS/MALICIOUS emails only (up to _MAX_EMAIL_RECORDS).

        Returns [] on storage error or no matches.
        """
        sender = (sender or "").lower().strip()
        originating_ips = [ip for ip in (originating_ips or []) if ip]
        shortener_domains = [d for d in (shortener_domains or []) if d]
        if not sender and not originating_ips and not shortener_domains:
            return []

        cutoff = time.time() - _WINDOW
        try:
            conn = self._connect()
            try:
                findings = []

                # Rule 1a: sender comes from multiple originating IPs
                if sender and originating_ips:
                    row = conn.execute(
                        "SELECT COUNT(DISTINCT ip) FROM sender_ip_log "
                        "WHERE sender=? AND seen_at>?",
                        (sender, cutoff),
                    ).fetchone()
                    distinct_ips = row[0] if row else 0
                    if distinct_ips >= 2:
                        rows = conn.execute(
                            "SELECT sender, message_id, seen_at, verdict "
                            "FROM sender_ip_log "
                            "WHERE sender=? AND seen_at>? AND verdict IN (?,?) "
                            "ORDER BY seen_at DESC LIMIT ?",
                            (sender, cutoff, *_FLAGGED, _MAX_EMAIL_RECORDS),
                        ).fetchall()
                        findings.append({
                            "rule": "behavioral_sender_ip_drift",
                            "ioc_value": sender,
                            "behavioral_count": distinct_ips,
                            "flagged_count": len(rows),
                            "emails": [
                                {"sender": r[0], "message_id": r[1],
                                 "seen_at": r[2], "verdict": r[3]}
                                for r in rows
                            ],
                        })

                # Rule 1b: IP used by 5+ distinct senders
                seen_ips = set()
                for ip in originating_ips:
                    if ip in seen_ips:
                        continue
                    seen_ips.add(ip)
                    row = conn.execute(
                        "SELECT COUNT(DISTINCT sender) FROM sender_ip_log "
                        "WHERE ip=? AND seen_at>?",
                        (ip, cutoff),
                    ).fetchone()
                    distinct_senders = row[0] if row else 0
                    if distinct_senders >= _MANY_SENDERS_THRESHOLD:
                        rows = conn.execute(
                            "SELECT sender, message_id, seen_at, verdict "
                            "FROM sender_ip_log "
                            "WHERE ip=? AND seen_at>? AND verdict IN (?,?) "
                            "ORDER BY seen_at DESC LIMIT ?",
                            (ip, cutoff, *_FLAGGED, _MAX_EMAIL_RECORDS),
                        ).fetchall()
                        findings.append({
                            "rule": "behavioral_ip_many_senders",
                            "ioc_value": ip,
                            "behavioral_count": distinct_senders,
                            "flagged_count": len(rows),
                            "emails": [
                                {"sender": r[0], "message_id": r[1],
                                 "seen_at": r[2], "verdict": r[3]}
                                for r in rows
                            ],
                        })

                # Rule 2: IP has previously sent link-shortener URLs
                seen_ips_short = set()
                for ip in originating_ips:
                    if ip in seen_ips_short:
                        continue
                    seen_ips_short.add(ip)
                    row = conn.execute(
                        "SELECT COUNT(*) FROM ip_shortener_log "
                        "WHERE ip=? AND seen_at>?",
                        (ip, cutoff),
                    ).fetchone()
                    count = row[0] if row else 0
                    if count >= 1:
                        rows = conn.execute(
                            "SELECT sender, message_id, seen_at, verdict "
                            "FROM ip_shortener_log "
                            "WHERE ip=? AND seen_at>? AND verdict IN (?,?) "
                            "ORDER BY seen_at DESC LIMIT ?",
                            (ip, cutoff, *_FLAGGED, _MAX_EMAIL_RECORDS),
                        ).fetchall()
                        findings.append({
                            "rule": "behavioral_ip_shortener",
                            "ioc_value": ip,
                            "behavioral_count": count,
                            "flagged_count": len(rows),
                            "emails": [
                                {"sender": r[0], "message_id": r[1],
                                 "seen_at": r[2], "verdict": r[3]}
                                for r in rows
                            ],
                        })

                # Rule 3: shortener domain used by other senders (MALICIOUS tier)
                for domain in shortener_domains:
                    row = conn.execute(
                        "SELECT COUNT(DISTINCT sender) FROM sender_shortener_log "
                        "WHERE shortener_domain=? AND sender!=? AND seen_at>?",
                        (domain, sender, cutoff),
                    ).fetchone()
                    other_senders = row[0] if row else 0
                    if other_senders >= 1:
                        rows = conn.execute(
                            "SELECT sender, message_id, seen_at, verdict "
                            "FROM sender_shortener_log "
                            "WHERE shortener_domain=? AND sender!=? AND seen_at>? "
                            "AND verdict IN (?,?) "
                            "ORDER BY seen_at DESC LIMIT ?",
                            (domain, sender, cutoff, *_FLAGGED, _MAX_EMAIL_RECORDS),
                        ).fetchall()
                        findings.append({
                            "rule": "behavioral_shared_shortener",
                            "ioc_value": domain,
                            "behavioral_count": other_senders,
                            "flagged_count": len(rows),
                            "emails": [
                                {"sender": r[0], "message_id": r[1],
                                 "seen_at": r[2], "verdict": r[3]}
                                for r in rows
                            ],
                        })

                return findings
            finally:
                conn.close()
        except (sqlite3.Error, OSError):
            return []

    def behavioral_lookup(
        self,
        sender,
        originating_ips,
        shortener_domains,
    ):
        """Return flag strings derived from behavioral_details().
        Kept for test compatibility; callers preferring rich data should use
        behavioral_details() directly."""
        details = self.behavioral_details(sender, originating_ips, shortener_domains)
        return [
            f"{d['rule']}:{d['ioc_value']}:{d['behavioral_count']}"
            for d in details
        ]


def get_default_store():
    return BehavioralCorrelationStore()
