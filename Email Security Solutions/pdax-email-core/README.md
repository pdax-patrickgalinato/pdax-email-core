# SEGS — Secure Email Gateway Suite

**PDAX-PROP-SEC-001** · Internal platform to detect, quarantine, and investigate email-based threats against PDAX's Google Workspace environment.

SEGS runs a 10-stage analysis pipeline on every inbound email — inspecting headers, sender identity, URLs, attachments, and content — and classifies each as CLEAN, LOW, SUSPICIOUS, or MALICIOUS. Quarantined emails appear in the SOC dashboard for analyst review, release, or escalation.

---

## Architecture overview

```
Internet → Google Workspace → Gmail inbox
                 │
          Pub/Sub notification
                 │
       SEGS Gmail Receiver (Path A)
                 │
         10-stage pipeline
          ┌──────┴──────┐
          │             │
        CLEAN        SUSPICIOUS / MALICIOUS
          │             │
     stays in         labeled SEGS-Quarantine
       inbox          removed from INBOX
                       │
              SOC Dashboard (review, release, escalate)
```

| Mode | What it does | Deployment |
|------|-------------|------------|
| **Path A** (active) | Post-delivery scanning via Gmail API. Email arrives in inbox; SEGS labels and moves suspicious/malicious mail. No MX changes. | ECS Fargate, ap-southeast-1 |
| **Path B** (future) | Pre-delivery SMTP gateway. MX record points to SEGS/Postfix; mail is inspected before it reaches the inbox. | Requires separate Postfix server |

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design.

---

## Documentation

| Guide | Audience | Contents |
|-------|----------|----------|
| [Architecture](docs/ARCHITECTURE.md) | All | System design, pipeline stages, Path A/B, data flow |
| [Deployment](docs/DEPLOYMENT.md) | Ops/DevOps | AWS ECS Fargate step-by-step deployment guide |
| [Gmail API Setup](docs/GMAIL_API_SETUP.md) | Ops/DevOps | GCP project, Pub/Sub, domain-wide delegation walkthrough |
| [Operations](docs/OPERATIONS.md) | SOC analysts | Day-to-day: reviewing alerts, releasing quarantine, managing users |
| [Configuration](docs/CONFIGURATION.md) | Ops/DevOps | All environment variables and configuration files |

---

## Repository layout

```
pdax-email-core/
├── app/                    Core analysis pipeline (transport-agnostic)
│   ├── pipeline/           10-stage detection: headers, sender, urls, attachments,
│   │                       content_ai, intel, verdict, …
│   ├── notify.py           Quarantine receiver notification emails
│   └── report.py           Slack alert formatting
├── gateway/
│   ├── gmail_receiver.py   Path A — Gmail API post-delivery receiver (port 8766)
│   └── hold_consumer.py    Path B — SMTP hold-queue consumer + quarantine CLI
├── server/                 FastAPI dashboard backend (port 8765)
│   └── routers/            Auth, policy, feed, enforcement, lists, notify config
├── dashboard/              Single-file vanilla JS/HTML dashboard (served as static)
├── rules/                  YAML/text configuration (detection weights, policy, lists)
├── ecs/                    ECS Fargate task definitions
├── deploy/                 Deployment scripts (push-images, update-service, secrets)
├── tests/                  Unit + integration test suite
├── samples/                Sample .eml files for testing
├── Dockerfile              Dashboard server container image
├── Dockerfile.receiver     Gmail receiver container image
├── entrypoint.sh           Container startup (writes credentials.json from secret)
└── .env.example            Environment variable reference
```

---

## Local development (offline, no cloud)

The pipeline runs fully offline for development and tuning:

```bash
# 1. Create virtualenv
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. Analyze a sample email
python3 analyze.py samples/phish_lookalike.eml

# 3. Run tests
python3 tests/test_core.py

# 4. Start the dashboard (local, no Gmail integration)
bash start_server.sh
# → http://127.0.0.1:8765
```

Default admin credentials are created on first run by the auth store. See `server/auth_store.py`.

---

## Production deployment (AWS ECS Fargate)

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for the complete guide.

Quick overview:

```bash
# 1. Set up secrets in AWS Secrets Manager
AWS_ACCOUNT_ID=123456789012 bash deploy/setup-secrets.sh

# 2. Build and push container images to ECR
AWS_ACCOUNT_ID=123456789012 bash deploy/push-images.sh

# 3. Deploy to ECS (after filling in REPLACE_ME placeholders in ecs/*.json)
AWS_ACCOUNT_ID=123456789012 EFS_FILESYSTEM_ID=fs-xxxx bash deploy/update-service.sh
```

---

## Pipeline stages

| # | Stage | What it checks |
|---|-------|---------------|
| 1 | Headers | SPF/DKIM/DMARC, Return-Path mismatch, Reply-To anomalies, Message-ID entropy |
| 2 | Sender | Lookalike domains (homoglyph + edit distance), VIP name spoofing, freemail personas |
| 3 | URLs | Anchor/href mismatch, lookalike URLs, risky TLDs, IP-literal links, redirect chains |
| 4 | Attachments | Banned extensions, HTML credential forms, SHA256 hashing, type-policy enforcement |
| 5 | Content AI | GLM/Claude analysis: urgency language, BEC patterns, prompt injection attempts |
| 6 | Brand/Visual | Trusted-platform abuse (TestFlight, DocuSign), service-abuse deception structure |
| 7 | Threat Intel | VirusTotal hash/URL lookup, AbuseIPDB IP reputation |
| 8 | IOC Correlation | Cross-message correlation of domains, IPs, hashes, sender patterns |
| 9 | Verdict | Score aggregation, hard overrides, LLM triage assist |
| 10 | Report | Slack alert, quarantine notification email, dashboard feed entry |

---

## Enforcement modes

Controlled by `SEG_ENFORCE` (or `rules/enforcement_mode.yaml` for live changes without redeployment):

| Mode | Behavior |
|------|----------|
| `shadow` | Log intended action only — all mail delivered normally. Use for tuning. |
| `quarantine` | SUSPICIOUS/MALICIOUS mail written to spool, removed from inbox. |
| `reject` | As quarantine, but MALICIOUS may also issue a 550 SMTP reject (Path B only). |

---

## Security posture

- **Dashboard**: internal-only, accessible only via JumpCloud VPN. TLS via ACM. Session cookies: `Secure`, `HttpOnly`, `SameSite=Strict`.
- **Gmail receiver**: public endpoint restricted to Google Pub/Sub IP ranges at the ALB security group level. Validated by `SEG_PUBSUB_TOKEN` shared secret.
- **Secrets**: all credentials in AWS Secrets Manager, injected at container start. No secrets in the Docker image or task definition plaintext.
- **Spool/data**: stored on EFS with transit encryption. `chmod 700` applied at startup.
- **CSP**: `script-src 'self' 'unsafe-inline'` (inline JS in dashboard). No external CDN dependencies.
- **Audit log**: all admin actions written to `data/activity_audit.jsonl` → CloudWatch → Wazuh.

---

## Compliance context

PDAX is a BSP-supervised VASP (Virtual Asset Service Provider) under RA 10173 (Data Privacy Act of the Philippines). SEGS processes email metadata and content within the organization's own AWS infrastructure (ap-southeast-1). The GLM content AI provider uses Vertex AI Model Garden — review data residency implications with DPO before processing live PII-containing emails.
