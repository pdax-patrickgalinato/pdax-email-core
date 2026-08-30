# SEGS — Gmail API Setup Guide

Path A is an **Abnormal-style Workspace API integration**. A super admin registers
SEGS’s service-account Client ID in Google Admin. The receiver then **calls Gmail
outbound** (history poll + fetch + read labels). It does not change Gmail labels.
Google never POSTs to a URL you host.
No Pub/Sub push subscription, no Route 53, no public receiver ALB.

This assumes a Google Workspace org at `pdax.ph` and admin access to Admin Console
and Google Cloud Console.

---

## What you register in Workspace

Same screen as other API vendors (Abnormal, etc.):

**Admin console → Security → Access and data control → API controls → Domain-wide delegation → Add new**

| Field | Value |
|-------|--------|
| Client ID | Unique ID of the `segs-gmail-reader` service account (numeric) |
| OAuth scopes | `https://www.googleapis.com/auth/gmail.readonly` |

`gmail.readonly` lets SEGS read messages and existing labels. It cannot change labels, send mail, or delete messages.

---

## Step 1 — GCP project

1. [console.cloud.google.com](https://console.cloud.google.com) → project `pdax-segs` (or existing prod project)
2. Note the **Project ID** (also used as `SEG_GLM_PROJECT_ID` if GLM runs in the same project)

Enable **Gmail API** only (`gmail.googleapis.com`). Pub/Sub is not required for poll mode.

```bash
gcloud services enable gmail.googleapis.com --project pdax-segs-123
```

---

## Step 2 — Service account + key

1. IAM & Admin → Service Accounts → Create: `segs-gmail-reader`
2. Keys → Add key → JSON → save as repo-root `credentials.json` (gitignored)
3. Store the JSON in AWS Secrets Manager as `SEGS_GMAIL_CREDENTIALS_JSON` (ECS writes the file at boot)

Note the service account **Unique ID** (OAuth2 Client ID) for step 3.

---

## Step 3 — Domain-wide delegation (the “register API” step)

1. [admin.google.com](https://admin.google.com)
2. Security → Access and data control → API controls → **Manage domain-wide delegation**
3. **Add new**
4. Client ID = Unique ID from step 2
5. Scope = `https://www.googleapis.com/auth/gmail.readonly`
6. Authorize

---

## Step 4 — Mailboxes to scan

`SEG_GMAIL_USERS` is the impersonation list. Start with a test mailbox.

```
SEG_GMAIL_USERS=security@pdax.ph
SEG_GMAIL_DOMAIN=pdax.ph
SEG_GMAIL_POLL_SECONDS=30
SEG_GMAIL_CREDENTIALS=credentials.json
```

The first poll **seeds the console** with the newest ~20 INBOX messages (local
copies only — Gmail is not modified), then records the current history id.
Mail that arrives after that is fetched, scored, and shown on the dashboard
Feed. Gmail labels are not changed.

---

## Step 5 — Run the receiver

```bash
# from repo root, with credentials.json and .env set
python3 -m workers.receiver
# health: http://127.0.0.1:8766/health
```

In ECS this is `workers.receiver:app` on port 8766. It only needs
**outbound HTTPS to Google**. It does not need to be on the public internet.

---

## Verify

1. Send a new message to a listed mailbox (after the receiver has started once)
2. Within `SEG_GMAIL_POLL_SECONDS`, CloudWatch `/segs/receiver` should log a verdict
3. Logs should show a verdict and the message’s **existing** Gmail labels (INBOX, etc.). Mail stays in the inbox.
4. Dashboard Feed is independent of Gmail labels in this phase.

If nothing happens:

- 403 from Gmail: DWD Client ID or scope mismatch, or the user is not in the Workspace
- empty polls: mail arrived *before* the first cursor snapshot (send a new one)
- `SEG_GMAIL_USERS` empty: receiver logs and skips

---

## Security notes

- `credentials.json` is never in the image or git. ECS injects `SEGS_GMAIL_CREDENTIALS_JSON`.
- Scope is `gmail.readonly` only. SEGS does not create or change labels.
- The receiver is not a public attack surface. Analyst APIs stay on the dashboard service.
- Rotate the service-account key quarterly: new JSON key → Secrets Manager → restart tasks → delete the old key in GCP.
