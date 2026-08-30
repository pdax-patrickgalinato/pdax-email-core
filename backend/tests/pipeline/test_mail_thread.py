"""Conversation threading — Gmail threadId + RFC Message-ID graph."""
import json

from backend.stores.mail_thread import assign_thread_keys, extract_message_ids, headers_from_raw


def test_extract_message_ids_bracketed_and_bare():
    assert extract_message_ids("<a@x.com> <b@x.com>") == ["<a@x.com>", "<b@x.com>"]
    assert extract_message_ids("mid@example.com") == ["<mid@example.com>"]
    assert extract_message_ids("") == []
    assert extract_message_ids("not an id with spaces") == []


def test_headers_from_raw_reads_thread_fields():
    raw = (
        b"From: a@example.com\n"
        b"Message-ID: <root@pdax.ph>\n"
        b"In-Reply-To: <parent@pdax.ph>\n"
        b"References: <root@pdax.ph> <parent@pdax.ph>\n"
        b"Subject: Re: hello\n"
        b"\n"
        b"body\n"
    )
    hdrs = headers_from_raw(raw)
    assert hdrs["message_id"] == "<root@pdax.ph>"
    assert hdrs["in_reply_to"] == "<parent@pdax.ph>"
    assert hdrs["from"] == "a@example.com"
    assert hdrs["subject"] == "Re: hello"
    assert "<root@pdax.ph>" in hdrs["references"]
    assert "<parent@pdax.ph>" in hdrs["references"]


def test_assign_thread_keys_gmail_id_groups_replies():
    entries = [
        {"id": "a", "mailbox": "jan@pdax.ph", "gmailThreadId": "t1",
         "messageId": "<a@x>", "inReplyTo": "", "references": ""},
        {"id": "b", "mailbox": "jan@pdax.ph", "gmailThreadId": "t1",
         "messageId": "<b@x>", "inReplyTo": "<a@x>", "references": "<a@x>"},
        {"id": "c", "mailbox": "jan@pdax.ph", "gmailThreadId": "t2",
         "messageId": "<c@x>", "inReplyTo": "", "references": ""},
    ]
    assign_thread_keys(entries)
    assert entries[0]["threadKey"] == entries[1]["threadKey"]
    assert entries[0]["threadCount"] == 2
    assert entries[2]["threadKey"] != entries[0]["threadKey"]
    assert entries[2]["threadCount"] == 1
    assert entries[0]["threadKey"].startswith("gmail:")


def test_assign_thread_keys_rfc_unions_via_in_reply_to():
    entries = [
        {"id": "root", "gmailThreadId": "", "messageId": "<root@x>",
         "inReplyTo": "", "references": ""},
        {"id": "reply", "gmailThreadId": "", "messageId": "<reply@x>",
         "inReplyTo": "<root@x>", "references": ""},
        {"id": "reply2", "gmailThreadId": "", "messageId": "<r2@x>",
         "inReplyTo": "<reply@x>", "references": "<root@x> <reply@x>"},
    ]
    assign_thread_keys(entries)
    keys = {e["threadKey"] for e in entries}
    assert len(keys) == 1
    assert entries[0]["threadCount"] == 3
    assert next(iter(keys)).startswith("rfc:")


def test_assign_thread_keys_singleton_without_ids():
    entries = [{"id": "lonely", "gmailThreadId": "", "messageId": "",
                "inReplyTo": "", "references": ""}]
    assign_thread_keys(entries)
    assert entries[0]["threadKey"] == "msg:lonely"
    assert entries[0]["threadCount"] == 1


def _seed_spool(root, bucket, qid, meta, body="hello"):
    from pathlib import Path
    dest = Path(root) / bucket / qid
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    (dest / "message.eml").write_bytes(
        f"From: {meta.get('from') or 'a@example.com'}\n"
        f"Subject: {meta.get('subject') or 'x'}\n\n{body}\n".encode()
    )
    return dest


def test_thread_prompt_context_includes_neighbors_and_current_marker(tmp_path):
    from backend.stores.mail_thread import thread_prompt_context

    a = _seed_spool(tmp_path, "gmail", "gmail-a", {
        "mailbox": "jan@pdax.ph", "gmail_thread_id": "t1",
        "from": "alice@pdax.ph", "subject": "Invoice", "verdict": "CLEAN",
        "ts": "2026-08-28T00:00:00+00:00", "primary_content": "Please see attached.",
    }, body="Please see attached.")
    b = _seed_spool(tmp_path, "gmail", "gmail-b", {
        "mailbox": "jan@pdax.ph", "gmail_thread_id": "t1",
        "from": "phish@evil.test", "subject": "Re: Invoice", "verdict": "LOW",
        "ts": "2026-08-28T00:10:00+00:00",
    }, body="Wire the funds now.")
    ctx = thread_prompt_context(b)
    assert ctx["count"] == 2
    assert "CURRENT MESSAGE" in ctx["transcript"]
    assert "alice@pdax.ph" in ctx["transcript"]
    assert "Please see attached." in ctx["transcript"]
    assert "body is in Subject/Body above" in ctx["transcript"]
    assert thread_prompt_context(a)["count"] == 2


def test_thread_prompt_context_singleton_is_empty(tmp_path):
    from backend.stores.mail_thread import thread_prompt_context

    dest = _seed_spool(tmp_path, "gmail", "gmail-lonely", {
        "mailbox": "jan@pdax.ph", "gmail_thread_id": "only-me",
        "from": "a@pdax.ph", "subject": "Hi",
    })
    assert thread_prompt_context(dest) == {}


def test_thread_prompt_context_sqs_payload_is_empty_without_siblings():
    from backend.stores.mail_thread import thread_prompt_context
    from backend.stores import spool

    assert thread_prompt_context(spool.payload("gmail-x"), {"gmail_thread_id": "t1"}) == {}


def test_thread_prompt_context_sqs_payload_uses_copy_rows(monkeypatch):
    from backend.stores.mail_thread import thread_prompt_context
    from backend.stores import assessments as store, spool

    store.upsert_copy(
        "gmail-a", gmail_thread_id="t1", from_addr="alice@pdax.ph",
        subject="Invoice", verdict="CLEAN", ai_done=1,
    )
    store.upsert_copy(
        "gmail-b", gmail_thread_id="t1", from_addr="phish@evil.test",
        subject="Re: Invoice", verdict="LOW", ai_done=1,
    )

    def read_meta(dest):
        qid = spool.dest_name(dest)
        if qid == "gmail-a":
            return {
                "gmail_thread_id": "t1", "from": "alice@pdax.ph",
                "subject": "Invoice", "verdict": "CLEAN", "ts": "2026-08-28T00:00:00+00:00",
                "primary_content": "Please see attached.",
            }
        return {
            "gmail_thread_id": "t1", "from": "phish@evil.test",
            "subject": "Re: Invoice", "verdict": "LOW", "ts": "2026-08-28T00:10:00+00:00",
        }

    monkeypatch.setattr("backend.stores.spool.read_meta", read_meta)
    ctx = thread_prompt_context(spool.payload("gmail-b"), {"gmail_thread_id": "t1"})
    assert ctx["count"] == 2
    assert "CURRENT MESSAGE" in ctx["transcript"]
    assert "alice@pdax.ph" in ctx["transcript"]
    assert "Please see attached." in ctx["transcript"]


def test_thread_prompt_context_ignores_other_mailbox_same_thread_id(monkeypatch):
    from backend.stores.mail_thread import thread_prompt_context
    from backend.stores import assessments as store, spool

    store.upsert_copy(
        "gmail-a", gmail_thread_id="t1", mailbox="jan@pdax.ph",
        gmail_message_id="m1", from_addr="alice@pdax.ph", ai_done=1,
    )
    store.upsert_copy(
        "gmail-b", gmail_thread_id="t1", mailbox="jan@pdax.ph",
        gmail_message_id="m2", from_addr="bob@pdax.ph", ai_done=1,
    )
    store.upsert_copy(
        "gmail-x", gmail_thread_id="t1", mailbox="other@pdax.ph",
        gmail_message_id="m9", from_addr="noise@pdax.ph", ai_done=1,
    )

    def read_meta(dest):
        qid = spool.dest_name(dest)
        return {
            "gmail-a": {
                "gmail_thread_id": "t1", "mailbox": "jan@pdax.ph",
                "from": "alice@pdax.ph", "subject": "Hi", "ts": "1",
            },
            "gmail-b": {
                "gmail_thread_id": "t1", "mailbox": "jan@pdax.ph",
                "from": "bob@pdax.ph", "subject": "Re: Hi", "ts": "2",
            },
            "gmail-x": {
                "gmail_thread_id": "t1", "mailbox": "other@pdax.ph",
                "from": "noise@pdax.ph", "subject": "Unrelated", "ts": "3",
            },
        }.get(qid) or {}

    monkeypatch.setattr("backend.stores.spool.read_meta", read_meta)
    ctx = thread_prompt_context(
        spool.payload("gmail-b"),
        {"gmail_thread_id": "t1", "mailbox": "jan@pdax.ph"},
    )
    assert ctx["count"] == 2
    assert "noise@pdax.ph" not in ctx["transcript"]


def test_propagate_thread_assessment_copies_to_siblings(tmp_path):
    from backend.stores.mail_thread import propagate_thread_assessment

    a = _seed_spool(tmp_path, "gmail", "gmail-a", {
        "mailbox": "jan@pdax.ph", "gmail_thread_id": "t1",
        "from": "a@pdax.ph", "subject": "Hi",
    })
    b = _seed_spool(tmp_path, "gmail", "gmail-b", {
        "mailbox": "jan@pdax.ph", "gmail_thread_id": "t1",
        "from": "b@evil.test", "subject": "Re: Hi",
        "thread_summary": "Hijack after a clean opener.",
        "thread_verdict": "SUSPICIOUS",
    })
    n = propagate_thread_assessment(b, "Hijack after a clean opener.", "suspicious")
    assert n == 1
    sibling = json.loads((a / "meta.json").read_text())
    assert sibling["thread_verdict"] == "SUSPICIOUS"
    assert "Hijack" in sibling["thread_summary"]
    assert sibling["thread_assessed_from"] == "gmail-b"

