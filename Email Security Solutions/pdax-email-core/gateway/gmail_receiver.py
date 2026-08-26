#!/usr/bin/env python3
"""Gmail API post-delivery receiver (Pub/Sub push model).

Architecture
------------
Google Workspace delivers mail normally → Gmail inbox.
This receiver subscribes to Gmail Pub/Sub notifications (users.watch),
fetches the raw message, runs the SEGS pipeline, and applies labels:

  CLEAN / LOW   → no action (message stays in inbox)
  SUSPICIOUS    → adds label "SEGS-Review",  removes INBOX
  MALICIOUS     → adds label "SEGS-Quarantine", removes INBOX, marks SPAM

Run alongside the main dashboard server (separate port):

    uvicorn gateway.gmail_receiver:app --port 8766 --reload

Prerequisites (Google Workspace Admin console — one-time setup)
----------------------------------------------------------------
1. Create a Pub/Sub topic in your GCP project, e.g. "segs-gmail".
2. Grant the Gmail service-account publish rights on the topic.
3. Create a push subscription pointing to:
       https://<your-hostname>:8766/pubsub
4. In Admin console → Security → API controls → Domain-wide delegation,
   add the service account's Client ID (103327719292725597248) with scope:
       https://www.googleapis.com/auth/gmail.modify
5. Set the environment variables below in .env before starting this server.

Environment variables
---------------------
  SEG_GMAIL_CREDENTIALS  path to credentials.json (default: credentials.json)
  SEG_GMAIL_TOPIC        full Pub/Sub topic name (projects/<proj>/topics/<topic>)
  SEG_GMAIL_DOMAIN       Google Workspace primary domain (e.g. pdax.ph)
  SEG_GMAIL_USERS        comma-separated list of mailboxes to watch, OR omit
                         to handle any mailbox pushed by the subscription
  SEG_PUBSUB_TOKEN       optional shared secret to validate push messages
                         (set in Pub/Sub push subscription as the auth token)
"""
from __future__ import annotations

import base64
import json
import os
import sys
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, Request, Response

# Pipeline and report helpers — same path tricks as hold_consumer.py
_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT))

from app.pipeline.runner import run_pipeline  # noqa: E402
from app.report import send_slack_alert  # noqa: E402

# ── config ────────────────────────────────────────────────────────────────────
_CREDS_PATH = os.environ.get("SEG_GMAIL_CREDENTIALS", str(_REPO_ROOT / "credentials.json"))
_TOPIC = os.environ.get("SEG_GMAIL_TOPIC", "")
_DOMAIN = os.environ.get("SEG_GMAIL_DOMAIN", "")
_USERS = [u.strip() for u in os.environ.get("SEG_GMAIL_USERS", "").split(",") if u.strip()]
_PUBSUB_TOKEN = os.environ.get("SEG_PUBSUB_TOKEN", "")

_SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]

# Labels SEGS creates (idempotent — created if absent)
_LABEL_REVIEW = "SEGS-Review"
_LABEL_QUARANTINE = "SEGS-Quarantine"

# ── Google client helpers ──────────────────────────────────────────────────────

def build_gmail_service(user_email: str):
    """Return an authorized Gmail API client impersonating *user_email* via DWD."""
    from google.oauth2 import service_account
    from googleapiclient.discovery import build

    creds = service_account.Credentials.from_service_account_file(
        _CREDS_PATH, scopes=_SCOPES
    ).with_subject(user_email)
    return build("gmail", "v1", credentials=creds, cache_discovery=False)


def _ensure_label(service, user_email: str, label_name: str) -> str:
    """Return the label id for *label_name*, creating it if it doesn't exist."""
    labels = service.users().labels().list(userId=user_email).execute()
    for lbl in labels.get("labels", []):
        if lbl["name"] == label_name:
            return lbl["id"]
    created = service.users().labels().create(
        userId=user_email,
        body={"name": label_name, "labelListVisibility": "labelShow",
              "messageListVisibility": "show"}
    ).execute()
    return created["id"]


def report_phishing(service, user_email: str, message_id: str) -> None:
    """Mark message as SPAM and remove it from INBOX — surfaces in Reported."""
    service.users().messages().modify(
        userId=user_email,
        id=message_id,
        body={"addLabelIds": ["SPAM"], "removeLabelIds": ["INBOX"]},
    ).execute()


def scan_message(user_email: str, message_id: str) -> dict:
    """Fetch raw EML, run SEGS pipeline, apply label action, return summary."""
    service = build_gmail_service(user_email)

    msg = service.users().messages().get(
        userId=user_email, id=message_id, format="raw"
    ).execute()

    raw = base64.urlsafe_b64decode(msg["raw"] + "==")
    result = run_pipeline(raw, source="gmail_api")

    verdict = result.verdict.value
    action = "none"

    if verdict == "MALICIOUS":
        label_id = _ensure_label(service, user_email, _LABEL_QUARANTINE)
        report_phishing(service, user_email, message_id)
        service.users().messages().modify(
            userId=user_email, id=message_id,
            body={"addLabelIds": [label_id], "removeLabelIds": ["INBOX"]},
        ).execute()
        action = "quarantined+spam"

    elif verdict == "SUSPICIOUS":
        label_id = _ensure_label(service, user_email, _LABEL_REVIEW)
        service.users().messages().modify(
            userId=user_email, id=message_id,
            body={"addLabelIds": [label_id], "removeLabelIds": ["INBOX"]},
        ).execute()
        action = "labeled-review"

    # Slack alert
    _maybe_slack_alert(result)

    return {
        "message_id": message_id,
        "user": user_email,
        "verdict": verdict,
        "score": result.composite_score,
        "action": action,
        "hard_override": result.hard_override,
    }


# ── Slack helper (reads rules/slack_config.yaml, same as hold_consumer.py) ────

def _maybe_slack_alert(result) -> None:
    import yaml
    path = _REPO_ROOT / "rules" / "slack_config.yaml"
    try:
        cfg = yaml.safe_load(path.read_text()) or {} if path.is_file() else {}
    except Exception:
        cfg = {}
    if not cfg.get("enabled"):
        return
    url = cfg.get("webhook_url", "").strip()
    if url:
        send_slack_alert(result, url, cfg.get("threshold", "SUSPICIOUS"))


# ── Watch renewal ─────────────────────────────────────────────────────────────

def renew_watch(user_email: str) -> dict:
    """Call users.watch() for *user_email* so Pub/Sub push stays active.

    Gmail watch tokens expire after ~7 days — call this daily from a cron job
    or on startup. Returns the watch response (expiration epoch ms + historyId).
    """
    from google.oauth2 import service_account
    from googleapiclient.discovery import build

    creds = service_account.Credentials.from_service_account_file(
        _CREDS_PATH, scopes=_SCOPES
    ).with_subject(user_email)
    service = build("gmail", "v1", credentials=creds, cache_discovery=False)
    return service.users().watch(
        userId=user_email,
        body={"topicName": _TOPIC, "labelIds": ["INBOX"]},
    ).execute()


# ── FastAPI app ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="SEGS Gmail API Receiver",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


@app.get("/health")
def health():
    return {"status": "ok", "service": "gmail_receiver"}


@app.post("/pubsub")
async def pubsub_push(request: Request):
    """Handle Pub/Sub push notification from Gmail watch subscription."""
    # Optional shared-secret validation (set SEG_PUBSUB_TOKEN in .env and in
    # the Pub/Sub subscription's "Authentication" field).
    if _PUBSUB_TOKEN:
        auth = request.headers.get("Authorization", "")
        if not auth.endswith(_PUBSUB_TOKEN):
            raise HTTPException(status_code=401, detail="Invalid push token")

    body = await request.json()
    message = body.get("message", {})
    data_b64 = message.get("data", "")
    if not data_b64:
        return Response(status_code=204)

    try:
        payload = json.loads(base64.b64decode(data_b64))
    except Exception:
        return Response(status_code=204)

    email_address = payload.get("emailAddress", "")
    history_id = payload.get("historyId")

    if not email_address or not history_id:
        return Response(status_code=204)

    # Optionally restrict to configured user list
    if _USERS and email_address not in _USERS:
        return Response(status_code=204)

    # Fetch new messages since historyId
    try:
        service = build_gmail_service(email_address)
        history_resp = service.users().history().list(
            userId=email_address,
            startHistoryId=str(history_id),
            historyTypes=["messageAdded"],
            labelId="INBOX",
        ).execute()
    except Exception as exc:
        print(f"[gmail_receiver] history.list failed for {email_address}: {exc}", file=sys.stderr)
        return Response(status_code=204)

    results = []
    for record in history_resp.get("history", []):
        for added in record.get("messagesAdded", []):
            msg_id = added.get("message", {}).get("id")
            if not msg_id:
                continue
            try:
                summary = scan_message(email_address, msg_id)
                results.append(summary)
                print(f"[gmail_receiver] {email_address} {msg_id} → {summary['verdict']} ({summary['action']})",
                      file=sys.stderr)
            except Exception as exc:
                print(f"[gmail_receiver] scan_message failed {msg_id}: {exc}", file=sys.stderr)

    return {"processed": len(results), "results": results}


@app.post("/watch/{user_email:path}")
def trigger_watch(user_email: str):
    """Admin endpoint — manually renew a Gmail watch for one mailbox."""
    if not _TOPIC:
        raise HTTPException(status_code=400, detail="SEG_GMAIL_TOPIC not configured")
    try:
        resp = renew_watch(user_email)
        return {"user": user_email, "watch": resp}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


if __name__ == "__main__":
    uvicorn.run("gateway.gmail_receiver:app", host="0.0.0.0", port=8766, reload=True)
