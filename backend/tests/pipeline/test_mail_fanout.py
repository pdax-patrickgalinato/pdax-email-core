"""Fan-out: same message delivered to other scanned inboxes / envelope recipients."""
import json
from pathlib import Path

from backend.stores.mail_fanout import fanout_prompt_context, propagate_fanout
from workers.pipeline.content_ai import _summarize_context


def _seed(root: Path, qid: str, mailbox: str, message_id: str, to_addr: str,
          body: str = "Please review the attached invoice."):
    dest = root / "gmail" / qid
    dest.mkdir(parents=True, exist_ok=True)
    meta = {
        "mailbox": mailbox,
        "from": "Vendor Billing <billing@vendor.example>",
        "to": to_addr,
        "subject": "Invoice 4419",
        "message_id": message_id,
        "verdict": "CLEAN",
        "primary_content": body,
    }
    (dest / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    (dest / "message.eml").write_bytes(
        f"From: billing@vendor.example\nTo: {to_addr}\n"
        f"Message-ID: {message_id}\nSubject: Invoice 4419\n\n{body}\n".encode()
    )
    return dest


def test_fanout_same_message_id_other_mailbox(tmp_path):
    a = _seed(tmp_path, "gmail-a", "jan@pdax.ph", "<blast@vendor.example>", "jan@pdax.ph")
    _seed(tmp_path, "gmail-b", "jessica@pdax.ph", "<blast@vendor.example>", "jessica@pdax.ph")
    _seed(tmp_path, "gmail-c", "kenneth@pdax.ph", "<blast@vendor.example>", "kenneth@pdax.ph")
    ctx = fanout_prompt_context(a)
    assert ctx["inbox_count"] == 2
    assert ctx["match"] == "message_id"
    assert "jessica@pdax.ph" in ctx["mailboxes"]
    assert "kenneth@pdax.ph" in ctx["mailboxes"]
    assert "jan@pdax.ph" not in ctx["mailboxes"]


def test_fanout_singleton_is_empty(tmp_path):
    dest = _seed(tmp_path, "gmail-lonely", "jan@pdax.ph", "<only@x>", "jan@pdax.ph")
    assert fanout_prompt_context(dest) == {}


def test_fanout_prompt_context_sqs_payload_is_empty():
    from backend.stores import spool
    from backend.stores.mail_fanout import _envelope_addrs

    dest = spool.payload("gmail-x")
    assert fanout_prompt_context(dest, {"mailbox": "jan@pdax.ph"}) == {}
    addrs = _envelope_addrs(dest, {
        "to": "jan@pdax.ph, jessica@pdax.ph",
        "cc": "kenneth@pdax.ph",
    })
    assert "jessica@pdax.ph" in addrs
    assert "kenneth@pdax.ph" in addrs


def test_fanout_content_fingerprint_when_message_ids_differ(tmp_path):
    body = "Wire the remaining balance to this account today."
    a = _seed(tmp_path, "gmail-a", "jan@pdax.ph", "<id-1@evil>", "jan@pdax.ph", body)
    _seed(tmp_path, "gmail-b", "allan@pdax.ph", "<id-2@evil>", "allan@pdax.ph", body)
    ctx = fanout_prompt_context(a)
    assert ctx["inbox_count"] == 1
    assert ctx["match"] == "content"
    assert "allan@pdax.ph" in ctx["mailboxes"]


def test_fanout_envelope_only_without_other_inboxes(tmp_path):
    dest = tmp_path / "gmail" / "gmail-env"
    dest.mkdir(parents=True)
    meta = {
        "mailbox": "jan@pdax.ph",
        "from": "alerts@saas.example",
        "to": "jan@pdax.ph, jessica@pdax.ph, kenneth@pdax.ph",
        "subject": "Weekly digest",
        "message_id": "<digest@saas.example>",
    }
    (dest / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    (dest / "message.eml").write_bytes(
        b"From: alerts@saas.example\n"
        b"To: jan@pdax.ph, jessica@pdax.ph, kenneth@pdax.ph\n"
        b"Message-ID: <digest@saas.example>\n"
        b"Subject: Weekly digest\n\nhello\n"
    )
    ctx = fanout_prompt_context(dest)
    assert ctx["inbox_count"] == 0
    assert ctx["envelope_count"] == 2
    assert ctx["match"] == "envelope"


def test_propagate_fanout_updates_siblings(tmp_path):
    a = _seed(tmp_path, "gmail-a", "jan@pdax.ph", "<blast@x>", "jan@pdax.ph")
    b = _seed(tmp_path, "gmail-b", "jessica@pdax.ph", "<blast@x>", "jessica@pdax.ph")
    n = propagate_fanout(b)
    assert n == 1
    sibling = json.loads((a / "meta.json").read_text())
    assert sibling["fanout_count"] == 1
    assert "jessica@pdax.ph" in sibling["fanout_mailboxes"]
    assert "fanout" in sibling["stages"]
    assert any(f.startswith("fanout_same_message:") for f in sibling["stages"]["fanout"]["flags"])


def test_summarize_context_includes_fanout():
    summary = _summarize_context({
        "fanout": {
            "inbox_count": 2,
            "mailboxes": ["jessica@pdax.ph", "kenneth@pdax.ph"],
            "transcript": "same message also delivered to 2 other scanned inboxes: jessica@pdax.ph, kenneth@pdax.ph",
        }
    })
    assert "Fan-out" in summary
    assert "jessica@pdax.ph" in summary
    assert "not a verdict" in summary
