# SEGS — Gmail API Setup Guide

This guide covers the complete GCP/Google Workspace configuration required for Path A (post-delivery Gmail API scanning). It assumes you already have a Google Workspace organization at `pdax.ph` and admin access to both the Google Admin Console and Google Cloud Console.

---

## Overview of what gets set up

| Component | Purpose |
|-----------|---------|
| GCP Project | Container for all Google Cloud resources |
| Service Account | Identity SEGS uses to call Gmail and Pub/Sub APIs |
| Domain-Wide Delegation (DWD) | Allows the service account to act on behalf of any mailbox in `pdax.ph` |
| Pub/Sub Topic + Subscription | Google pushes a notification to SEGS every time a new email arrives |
| Gmail Watch | Per-mailbox subscription that connects Gmail to the Pub/Sub topic |

---

## Step 1 — Create or select a GCP project

1. Go to [console.cloud.google.com](https://console.cloud.google.com)
2. Create a new project named `pdax-segs` (or use your existing `pdax-prod` project)
3. Note the **Project ID** (e.g. `pdax-segs-123`) — this becomes `SEG_GLM_PROJECT_ID`

---

## Step 2 — Enable required APIs

In the GCP Console → APIs & Services → Library, enable:

- **Gmail API** (`gmail.googleapis.com`)
- **Cloud Pub/Sub API** (`pubsub.googleapis.com`)

```bash
# Or via gcloud:
gcloud services enable gmail.googleapis.com pubsub.googleapis.com \
  --project pdax-segs-123
```

---

## Step 3 — Create a service account

1. GCP Console → IAM & Admin → Service Accounts → Create Service Account
2. Name: `segs-gmail-reader`
3. Description: `SEGS Gmail API and Pub/Sub access`
4. Click **Create and Continue**
5. Skip role assignment at this screen (roles granted at resource level below)
6. Click **Done**

Note the **Service Account Email** (e.g. `segs-gmail-reader@pdax-segs-123.iam.gserviceaccount.com`)

### Create and download a key

1. Click the service account → Keys tab → Add Key → Create new key
2. Key type: **JSON**
3. Click **Create** — downloads `pdax-segs-123-xxxx.json`
4. Rename to `credentials.json` and place it in the repo root
5. **Never commit this file** — it is in `.gitignore` and must stay there
6. Store its contents in AWS Secrets Manager via `bash deploy/setup-secrets.sh`

---

## Step 4 — Create the Pub/Sub topic

```bash
gcloud pubsub topics create segs-gmail \
  --project pdax-segs-123
```

Full topic name: `projects/pdax-segs-123/topics/segs-gmail`
This becomes `SEG_GMAIL_TOPIC`.

### Grant Gmail permission to publish to the topic

Gmail's service account (`gmail-api-push@system.gserviceaccount.com`) must be able to publish:

```bash
gcloud pubsub topics add-iam-policy-binding segs-gmail \
  --project pdax-segs-123 \
  --member serviceAccount:gmail-api-push@system.gserviceaccount.com \
  --role roles/pubsub.publisher
```

### Grant the SEGS service account permission to subscribe

```bash
gcloud pubsub topics add-iam-policy-binding segs-gmail \
  --project pdax-segs-123 \
  --member serviceAccount:segs-gmail-reader@pdax-segs-123.iam.gserviceaccount.com \
  --role roles/pubsub.subscriber
```

---

## Step 5 — Create the Pub/Sub push subscription

This step is done **after** the SEGS receiver is deployed and `segs-mail.pdax.ph` is accessible.

In GCP Console → Pub/Sub → Topics → `segs-gmail` → Subscriptions → Create Subscription:

| Field | Value |
|-------|-------|
| Subscription ID | `segs-gmail-push` |
| Delivery type | Push |
| Endpoint URL | `https://segs-mail.pdax.ph/pubsub` |
| Enable authentication | On |
| Service account | `segs-gmail-reader@pdax-segs-123.iam.gserviceaccount.com` |
| Audience | `https://segs-mail.pdax.ph/pubsub` |
| Acknowledgement deadline | 60 seconds |
| Retry policy | Retry with exponential backoff |
| Min backoff | 10 seconds |
| Max backoff | 600 seconds |
| Message retention | 7 days |

Alternatively, use the token-based authentication approach (simpler, no service account OIDC needed):
- Disable "Enable authentication"
- Set `SEG_PUBSUB_TOKEN` to a random 32-byte token
- SEGS validates `Authorization: Bearer <token>` on every push request

```bash
# Or via gcloud (token approach):
gcloud pubsub subscriptions create segs-gmail-push \
  --project pdax-segs-123 \
  --topic segs-gmail \
  --push-endpoint "https://segs-mail.pdax.ph/pubsub" \
  --push-auth-token-audience "https://segs-mail.pdax.ph/pubsub" \
  --ack-deadline 60 \
  --min-retry-delay 10s \
  --max-retry-delay 600s
```

---

## Step 6 — Configure Domain-Wide Delegation

Domain-Wide Delegation (DWD) allows the SEGS service account to call Gmail API on behalf of any mailbox in `pdax.ph` without requiring each user to individually authorize the application.

### 6a — Note the service account's OAuth2 Client ID

1. GCP Console → IAM & Admin → Service Accounts → click `segs-gmail-reader`
2. Note the **Unique ID** (a number like `103327719292725597248`) — this is the OAuth2 Client ID

### 6b — Enable DWD in Google Admin Console

1. Go to [admin.google.com](https://admin.google.com)
2. Security → Access and data control → API controls → Domain-wide delegation
3. Click **Add new**
4. **Client ID**: paste the Unique ID from 6a
5. **OAuth scopes**: add `https://www.googleapis.com/auth/gmail.modify`
6. Click **Authorize**

> `gmail.modify` allows SEGS to read messages and modify labels. It does NOT allow sending, deleting, or accessing contacts.

### 6c — Note the sub-scope for monitoring

`SEG_GMAIL_USERS` is the list of mailboxes SEGS will monitor. The service account impersonates each address listed. Start with a security or test mailbox before expanding to all users.

```
SEG_GMAIL_USERS=security@pdax.ph,pat@pdax.ph
```

---

## Step 7 — Register Gmail watches

A Gmail watch connects a mailbox to the Pub/Sub topic. It expires after 7 days and must be renewed.

### Via SEGS dashboard
After deploying SEGS: Settings → Gmail Watches → Register watch for each user.

### Via API directly (for testing)

```python
from google.oauth2 import service_account
from googleapiclient.discovery import build

creds = service_account.Credentials.from_service_account_file(
    'credentials.json',
    scopes=['https://www.googleapis.com/auth/gmail.modify']
).with_subject('security@pdax.ph')

service = build('gmail', 'v1', credentials=creds)
service.users().watch(userId='me', body={
    'topicName': 'projects/pdax-segs-123/topics/segs-gmail',
    'labelIds': ['INBOX'],
    'labelFilterBehavior': 'INCLUDE'
}).execute()
```

### Automatic renewal

SEGS renews watches automatically on every container restart via the lifespan hook in `gateway/gmail_receiver.py`. The EventBridge Lambda (`deploy/lambda_renew_watches.py`) provides a daily fallback in case the service runs for >7 days without a restart.

---

## Step 8 — Verify end-to-end

1. Send a test email to a monitored mailbox
2. Check GCP Console → Pub/Sub → `segs-gmail-push` → Metrics → Message count should increment
3. Check CloudWatch `/segs/receiver` logs — you should see a pipeline run log within 30 seconds
4. Check the SEGS dashboard Feed — the email should appear with a verdict

If the message does not appear:
- Check that the Gmail watch is registered: `GET https://segs.pdax.ph/api/watches` (admin session)
- Check that the Pub/Sub push subscription is active and the endpoint is reachable
- Check receiver logs for `403 Forbidden` (token mismatch) or `connect timeout` (ALB/network issue)

---

## Quarterly maintenance

### Refresh Google Pub/Sub IP list (for WAF)

```bash
curl -s https://www.gstatic.com/ipranges/cloud.json \
  | python3 -c "import json,sys; [print(p['ipv4Prefix']) for p in json.load(sys.stdin)['prefixes'] if 'ipv4Prefix' in p]" \
  > deploy/google-pubsub-ips.txt
# Then update the WAF IP set
```

### Rotate service account key

1. GCP Console → Service Accounts → `segs-gmail-reader` → Keys → Add Key → Create new key (JSON)
2. Download new `credentials.json`
3. Run `bash deploy/setup-secrets.sh` to update Secrets Manager
4. Run `bash deploy/update-service.sh` to restart ECS tasks (picks up new secret)
5. Delete the old key from GCP Console

---

## Security notes

- **`credentials.json` is never in the Docker image or git repository.** It is stored in AWS Secrets Manager as `SEGS_GMAIL_CREDENTIALS_JSON` (single-line JSON string) and written to disk at container start by `entrypoint.sh`.
- **DWD scope is `gmail.modify` only.** SEGS cannot send email, delete messages, or access other APIs.
- **The Pub/Sub push endpoint (`/pubsub`) is the only public SEGS surface.** All other API routes are behind the internal ALB (VPN-only). The receiver validates each push request with a shared token (`SEG_PUBSUB_TOKEN`).
- **Service account keys should be rotated quarterly** per PDAX security policy. The rotation procedure is documented above.
