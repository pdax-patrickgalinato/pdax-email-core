# SEGS Deployment — Google Workspace

**Integrating SEGS with Google Workspace (Gmail) — the post-delivery API model.**

Last updated: 2026-08-25

This is the Workspace-specific companion to [`DEPLOYMENT.md`](DEPLOYMENT.md).
Phases 1–6 and 9 of that guide (provision, install, `.env`, admin setup,
hardening, tuning, operations) apply unchanged — **do those first**. This
document replaces **Phase 0** (model choice) and **Phase 7** (mail-flow
integration) with Workspace specifics.

---

## Which integration model fits Google Workspace

You have two realistic options. The first is strongly recommended.

| Option | How it works | Effort | Recommendation |
|---|---|---|---|
| **C. Post-delivery API (clawback)** | Gmail notifies SEGS the moment mail arrives; SEGS scans it and, if malicious, pulls it from the inbox into a quarantine label — usually within seconds, before the user acts | Moderate (build a receiver) | ✅ **Recommended** — no MX change, no mail-flow risk, reversible |
| **B. Inline SMTP gateway** | Change your MX / inbound routing so mail passes *through* SEGS before Gmail delivers it | High (SEGS must run as a full SMTP MTA in front of Workspace) | Only if you require true pre-delivery blocking |

The rest of this guide details **Option C**. Option B is summarized at the end.

### Why post-delivery is the right default here

- **No MX change, no delivery risk.** Mail keeps flowing through Google normally; SEGS observes and acts *after* delivery. If SEGS is down, mail is unaffected.
- **Reversible.** "Quarantine" is just a Gmail label move (remove `INBOX`, add `SEGS-Quarantine`). A false positive is one label change to undo — nothing is ever lost.
- **Fast enough.** Gmail push notifications fire within seconds of arrival, so a malicious message is typically clawed back before the recipient opens it.
- **Reuses the whole detection core.** `run_pipeline(raw, source="gmail_api")` already exists; you're building the *glue*, not the brain.

---

## Architecture (Option C)

```
   Inbound mail ─► Google Workspace (Gmail delivers normally)
                         │
                         │ 1. new-message push notification
                         ▼
                   Google Pub/Sub topic
                         │ 2. SEGS receiver is notified
                         ▼
        ┌────────────────────────────────────────────┐
        │  SEGS Gmail receiver  (the piece you build)  │
        │  3. fetch raw .eml via Gmail API             │
        │  4. run_pipeline(raw, source="gmail_api")    │
        │  5. verdict → Gmail action:                  │
        │       CLEAN/LOW      → leave in inbox         │
        │       SUSPICIOUS/MAL → remove INBOX label +   │
        │                        add SEGS-Quarantine    │
        └───────────────────────┬──────────────────────┘
                                 │ 6. analysts review in the SEGS console
                                 ▼
                     release (restore INBOX) / keep-quarantined
```

**What's ready:** the detection pipeline, the console, quarantine/re-eval logic.
**What you build:** the Gmail receiver in the dashed box (steps 1–5) — a few
hundred lines. I can help write it.

---

## Phase 0-GW — Google Cloud & Workspace setup

You need a GCP project (for the API + service account) and Workspace admin
access (to authorize domain-wide delegation).

### 1. Create the GCP project & enable APIs

```bash
gcloud projects create segs-gw --name="SEGS Gmail Integration"
gcloud config set project segs-gw
gcloud services enable gmail.googleapis.com pubsub.googleapis.com
```

### 2. Create a service account (SEGS's identity)

```bash
gcloud iam service-accounts create segs-gmail \
  --display-name="SEGS Gmail scanner"
# Create and download a key (this is a powerful secret — protect it like a password)
gcloud iam service-accounts keys create /opt/segs/app/gw-service-account.json \
  --iam-account=segs-gmail@segs-gw.iam.gserviceaccount.com
```

Note the service account's **numeric Client ID** (Admin console needs it):
`gcloud iam service-accounts describe segs-gmail@segs-gw.iam.gserviceaccount.com --format='value(oauth2ClientId)'`

### 3. Authorize domain-wide delegation (Workspace Admin console)

This lets the service account act on your users' mailboxes. In
**admin.google.com → Security → Access and data control → API controls →
Domain-wide delegation → Add new**:

- **Client ID:** the numeric OAuth client ID from step 2.
- **Scopes** (least privilege — only what clawback needs):
  ```
  https://www.googleapis.com/auth/gmail.modify
  ```
  `gmail.modify` allows reading a message and moving labels (quarantine), but
  **not** permanent deletion — deliberately. Do not grant broader scopes.

> ⚠️ **Domain-wide delegation is powerful** — that service-account key can read
> and relabel any mailbox in your domain. Store the key `600`, owned by the
> `segs` user, never in git (it's covered by `.gitignore`), and rotate it on a
> schedule. Treat it as your most sensitive secret.

### 4. Set up the Pub/Sub topic for push notifications

```bash
gcloud pubsub topics create segs-gmail-events
# Gmail's system account must be allowed to publish to it:
gcloud pubsub topics add-iam-policy-binding segs-gmail-events \
  --member="serviceAccount:gmail-api-push@system.gserviceaccount.com" \
  --role="roles/pubsub.publisher"
gcloud pubsub subscriptions create segs-gmail-sub --topic=segs-gmail-events
```

---

## Phase 7-GW — Build & run the Gmail receiver

The receiver is the glue between Gmail and `run_pipeline()`. Its shape:

```python
# gateway/gmail_receiver.py  (to be built — sketch)
from google.oauth2 import service_account
from googleapiclient.discovery import build
from app.pipeline.runner import run_pipeline

SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]
QUARANTINE_LABEL = "SEGS-Quarantine"

def _gmail_for(user_email: str):
    creds = service_account.Credentials.from_service_account_file(
        "/opt/segs/app/gw-service-account.json", scopes=SCOPES
    ).with_subject(user_email)          # domain-wide delegation: impersonate the mailbox
    return build("gmail", "v1", credentials=creds)

def scan_message(user_email: str, msg_id: str):
    svc = _gmail_for(user_email)
    raw = svc.users().messages().get(userId="me", id=msg_id, format="raw").execute()
    import base64
    eml = base64.urlsafe_b64decode(raw["raw"])

    result = run_pipeline(eml, source="gmail_api")   # ← the SEGS detection core

    if result.disposition.value in ("QUARANTINE", "REJECT"):
        _ensure_label(svc, QUARANTINE_LABEL)
        svc.users().messages().modify(
            userId="me", id=msg_id,
            body={"removeLabelIds": ["INBOX"],
                  "addLabelIds": [_label_id(svc, QUARANTINE_LABEL)]},
        ).execute()
    # CLEAN / LOW → leave in place. Log everything for the audit trail.
```

**Wiring options for step 1–2 (getting notified of new mail):**

- **Push (real-time, recommended):** call `users.watch()` per mailbox pointing at
  the Pub/Sub topic; a subscriber process pulls from `segs-gmail-sub`, reads the
  `historyId`, calls `users.history.list` to find `messagesAdded`, then
  `scan_message()`. **`watch` expires every 7 days — renew it daily via cron.**
- **Polling (simpler, near-real-time):** a cron job every 1–2 min runs
  `users.messages.list(q="newer_than:5m -in:sent")` per mailbox and scans new
  IDs. Easier to build; heavier at scale. Good for a first cut / small domains.

Run the receiver as its own systemd service alongside the console.

---

## Phase 8-GW — Shadow first, then enforce (adapted to Gmail)

Same safety ramp as the base guide, expressed in Gmail actions:

| Stage | `SEG_ENFORCE` | What the receiver does |
|---|---|---|
| **Shadow** | `shadow` | Scan and **log** the intended action in the SEGS console/audit — but **do not** move any message. Watch for false positives. |
| **Quarantine** | `quarantine` | Actually relabel SUSPICIOUS/MALICIOUS out of the inbox into `SEGS-Quarantine`. Reversible from the console. |
| **Reject** | `reject` | For confirmed MALICIOUS, optionally `trash` instead of label (still recoverable from Gmail Trash for 30 days). Enable only after quarantine is proven. |

Stay in shadow until false-positives on your real mail are essentially zero.
Because quarantine here is a label move, even "enforcing" is fully reversible —
which makes Workspace one of the safer platforms to graduate on.

---

## The analyst loop (unchanged)

Quarantined mail shows up in the SEGS console's live feed. An analyst can
**release** (receiver restores the `INBOX` label), **keep-quarantined**, or
**re-evaluate** as detection improves — every action audit-logged. Deep-dive any
message on the Analyze page.

---

## A note on the AI stage for Workspace

Your mail already lives in Google. Even so, the AI content stage is a separate
data-governance decision: pointing it at **Gemini/GLM** sends content to a
*different* Google (or third-party) API surface. **Self-hosted Ollama remains
the recommended production choice** so email content never leaves your own
infrastructure — set `SEG_CONTENT_PROVIDER=ollama` and enable `SEG_LLM_TRIAGE=1`
so only ambiguous mail spends a model call.

---

## Option B — True inline (only if you must block pre-delivery)

Google Workspace supports routing inbound mail through an external gateway
before Gmail delivers it (**Admin console → Apps → Google Workspace → Gmail →
Hosts + Routing → Inbound gateway**). To use it, SEGS must run as a real **SMTP
MTA** (e.g. Postfix in front) that:

1. Receives inbound mail (your MX points at it),
2. Scans each message with `run_pipeline(source="smtp_hold")`,
3. Relays clean mail on to Google (via Google's inbound SMTP / a routing rule),
   and holds/rejects the rest.

This is a larger build (SEGS-as-MTA + the `EnforcementClient` adapter from the
base guide) and it puts SEGS in the critical delivery path. **For Google
Workspace, post-delivery clawback (Option C) gets you ~95% of the protection
with a fraction of the risk** — start there.

---

## Quick reference — Workspace integration checklist

```
[ ] Base guide Phases 1–6 done (host, install, .env, admin, hardening, tuning)
[ ] GCP project created; Gmail API + Pub/Sub enabled
[ ] Service account created; key stored 600, owned by segs, gitignored
[ ] Domain-wide delegation authorized in Admin console (scope: gmail.modify only)
[ ] Pub/Sub topic + subscription created; gmail push publisher bound
[ ] gmail_receiver.py built (watch/poll → fetch → run_pipeline → relabel)
[ ] Receiver running as a systemd service
[ ] SEG_ENFORCE=shadow — observe false positives on real mail
[ ] Graduate: shadow → quarantine → (optional) reject
```

Want help building `gmail_receiver.py`? I can write the full watch + Pub/Sub +
clawback implementation against your project/topic names.
