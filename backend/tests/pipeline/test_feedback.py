"""Analyst feedback store, portable pack, and learned-benign override."""
from __future__ import annotations

from types import SimpleNamespace

from backend.stores import feedback as fb
from backend.models import Disposition, Verdict
from workers.pipeline.runner import run_pipeline


def _eml(from_addr: str, body: str = "hello") -> bytes:
    return (
        f"From: {from_addr}\r\n"
        f"To: victim@pdax.ph\r\n"
        f"Subject: hello\r\n"
        f"Message-ID: <fb-test@example.com>\r\n"
        f"\r\n"
        f"{body}\r\n"
    ).encode()


def test_extract_indicators_from_raw_and_meta():
    meta = {
        "from": "News <news@vendor.example>",
        "subject": "Hi",
        "iocs": {"urls": ["https://zoom.us/j/abc"], "domains": ["cdn.example"]},
    }
    raw = _eml("news@vendor.example", "See https://zoom.us/j/abc")
    pairs = fb.extract_indicators(meta, raw)
    kinds = set(pairs)
    assert ("sender_address", "news@vendor.example") in kinds
    assert ("sender_domain", "vendor.example") in kinds
    assert ("url_host", "zoom.us") in kinds


def test_record_rebuilds_portable_pack(tmp_path):
    db = tmp_path / "fb.sqlite3"
    pack_file = tmp_path / "good_indicators.json"
    meta = {"from": "ok@pdax.ph", "subject": "Invoice copy", "verdict": "LOW", "score": 22.0}
    out = fb.record_benign(
        queue_id="gmail-abc",
        meta=meta,
        raw=_eml("ok@pdax.ph"),
        actor="jan",
        db_path=db,
        pack_file=pack_file,
    )
    assert out["label"] == "benign"
    assert any(i["kind"] == "sender_address" and i["value"] == "ok@pdax.ph" for i in out["indicators"])
    loaded = fb.load_pack(pack_file)
    assert loaded["version"] == 1
    values = {i["value"]: i["confirmations"] for i in loaded["indicators"]}
    assert values["ok@pdax.ph"] == 1
    assert values["pdax.ph"] == 1


def test_import_pack_preserves_confirmations(tmp_path):
    db = tmp_path / "fb.sqlite3"
    pack_file = tmp_path / "good_indicators.json"
    incoming = {
        "version": 1,
        "indicators": [
            {"kind": "sender_address", "value": "trusted@corp.example", "confirmations": 4},
            {"kind": "url_host", "value": "zoom.us", "confirmations": 2},
        ],
    }
    fb.import_pack(incoming, actor="admin", db_path=db, pack_file=pack_file)
    loaded = fb.load_pack(pack_file)
    by = {(i["kind"], i["value"]): i["confirmations"] for i in loaded["indicators"]}
    assert by[("sender_address", "trusted@corp.example")] == 4
    assert by[("url_host", "zoom.us")] == 2


def test_learned_override_on_known_address(tmp_path, monkeypatch):
    pack = {
        "version": 1,
        "indicators": [
            {"kind": "sender_address", "value": "friend@vendor.example", "confirmations": 1},
        ],
    }
    monkeypatch.setattr(fb, "load_pack", lambda path=None: pack)
    result = run_pipeline(_eml("friend@vendor.example"), source="file")
    assert result.hard_override == "learned_benign"
    assert result.disposition == Disposition.DELIVER
    assert result.verdict in (Verdict.CLEAN, Verdict.LOW, Verdict.SUSPICIOUS, Verdict.MALICIOUS)


def test_hard_intel_blocks_learned_override():
    result = SimpleNamespace(
        hard_override=None,
        reasons=["intel_hash:deadbeef"],
        disposition=Disposition.LOG,
        disposition_reason="",
    )
    pe = SimpleNamespace(from_addr="friend@vendor.example", urls=lambda: [])
    fb.apply_learned_override(
        result, pe, {"benign_sender": True, "sender_confirmations": 2},
    )
    assert result.hard_override is None


def test_match_sender_ignores_freemail_domain(monkeypatch):
    monkeypatch.setattr(fb, "_is_freemail", lambda d: d == "gmail.com")
    pack = {
        "indicators": [
            {"kind": "sender_domain", "value": "gmail.com", "confirmations": 9},
        ],
    }
    info = fb.match_sender("user@gmail.com", "gmail.com", pack=pack)
    assert info["benign_domain"] is False
    assert info["benign_sender"] is False
