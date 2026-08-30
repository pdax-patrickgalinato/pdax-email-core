"""Runtime operator switches shared by the API and split workers.

Gmail fetch pause lives here (not an env var) so Settings can stop inbound
poll without restarting the poll task. Assessment workers keep draining
copies already in the spool.
"""
from __future__ import annotations

import time

_GMAIL_FETCH = "gmail_fetch"
_OFF = frozenset({"0", "false", "off", "no"})


def _connect():
    from backend.stores import assessments as store
    return store._connect()


def _row_value(row) -> str:
    if row is None:
        return ""
    try:
        return str(row["value"] or "")
    except (KeyError, IndexError, TypeError):
        try:
            return str(row[0] or "")
        except (KeyError, IndexError, TypeError):
            return ""


def gmail_fetch_enabled() -> bool:
    """True unless an admin paused inbound Gmail poll. Fail open on errors."""
    try:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT value FROM runtime_settings WHERE key = ?",
                (_GMAIL_FETCH,),
            ).fetchone()
        finally:
            conn.close()
    except Exception:
        return True
    if row is None:
        return True
    return _row_value(row).strip().lower() not in _OFF


def gmail_fetch_snapshot() -> dict:
    enabled = True
    updated_by = ""
    updated_at = ""
    try:
        conn = _connect()
        try:
            row = conn.execute(
                "SELECT value, updated_by, updated_at FROM runtime_settings WHERE key = ?",
                (_GMAIL_FETCH,),
            ).fetchone()
        finally:
            conn.close()
    except Exception:
        row = None
    if row is not None:
        enabled = _row_value(row).strip().lower() not in _OFF
        try:
            updated_by = str(row["updated_by"] or "")
            ts = float(row["updated_at"] or 0)
        except (KeyError, IndexError, TypeError, ValueError):
            updated_by = str(row[1] or "") if len(row) > 1 else ""
            try:
                ts = float(row[2] or 0)
            except (TypeError, ValueError, IndexError):
                ts = 0
        if ts:
            updated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))
    return {
        "gmail_fetch": enabled,
        "updated_by": updated_by,
        "updated_at": updated_at,
    }


def set_gmail_fetch(enabled: bool, actor: str = "") -> dict:
    now = time.time()
    conn = _connect()
    try:
        conn.execute("DELETE FROM runtime_settings WHERE key = ?", (_GMAIL_FETCH,))
        conn.execute(
            "INSERT INTO runtime_settings (key, value, updated_at, updated_by) "
            "VALUES (?, ?, ?, ?)",
            (_GMAIL_FETCH, "1" if enabled else "0", now, (actor or "").strip()),
        )
        conn.commit()
    finally:
        conn.close()
    return gmail_fetch_snapshot()
