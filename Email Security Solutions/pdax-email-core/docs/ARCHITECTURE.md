# SEGS — Architecture

## Overview

SEGS (Secure Email Gateway Suite) is a multi-stage threat detection platform that inspects inbound email for PDAX's Google Workspace environment. The core pipeline is transport-agnostic: it receives a raw `.eml` message and returns a structured verdict. Transport adapters (Path A and Path B) handle how messages arrive and what happens to them afterward.

---

## Two integration paths

### Path A — Post-delivery scanning (current)

Google Workspace delivers mail normally. Gmail fires a Pub/Sub push notification to SEGS. SEGS fetches the message via the Gmail API, runs the pipeline, and relabels or moves it depending on the verdict.

```
Sender → Google (SMTP)
              │
              ▼
         Gmail inbox
              │
        Pub/Sub push notification
              │
              ▼
    SEGS Gmail Receiver (8766)
    POST /pubsub
              │
        fetch message via Gmail API
              │
              ▼
        10-stage pipeline
         ┌────┴─────┐
       CLEAN     SUSPICIOUS
         │       MALICIOUS
         │          │
     no action    Gmail API:
                  - remove INBOX label
                  - apply SEGS-Quarantine
                  - apply SEGS-Review
                  │
                  ▼
            SOC dashboard
            (review / release / escalate)
```

**Advantages**: No MX change. Google's spam filtering still runs. Deployment is a single HTTPS endpoint in front of ECS Fargate. False positives can be released back to the inbox with one click.

**Limitation**: Mail is in the inbox briefly before SEGS can act (~5-30 seconds). A user who opens phishing mail in that window is exposed. This is acceptable in the monitoring phase.

---

### Path B — Pre-delivery SMTP gateway (future)

MX records point to a SEGS-controlled Postfix server. All inbound SMTP arrives at Postfix/Rspamd. SEGS milter intercepts the message, runs the pipeline, and either accepts (forwards to Google Workspace) or rejects/quarantines before delivery.

```
Sender → Postfix/Rspamd (SEGS)
              │
        milter intercept
              │
        10-stage pipeline
         ┌────┴─────┐
       CLEAN     SUSPICIOUS
         │       MALICIOUS
         │          │
    forward to    quarantine spool
    Google WS     or SMTP 550 reject
                       │
                  SOC dashboard
                  (re-eval / release)
```

**Advantages**: Zero-exposure. Malicious mail never reaches the inbox. SMTP-level rejection sends a bounce to the sender (audit trail). Works for any mail domain, not just Google Workspace.

**Required to activate**: A `PostfixMilterClient` (see [gateway/README.md](../gateway/README.md)), an MX DNS change, and `SEG_ENFORCE=quarantine`. The quarantine spool, dashboard, and re-evaluation UI are already in place.

---

## System components

```
┌─────────────────────────────── AWS (ap-southeast-1) ───────────────────────────────┐
│                                                                                     │
│  Internal ALB                        Internet-facing ALB                           │
│  segs.pdax.ph                        segs-mail.pdax.ph                            │
│  (VPN-only, dashboard)               (Google IPs only, receiver)                  │
│         │                                   │                                      │
│         ▼                                   ▼                                      │
│  ECS Fargate                          ECS Fargate                                  │
│  segs-dashboard                       segs-receiver                               │
│  uvicorn :8765                        uvicorn :8766                               │
│  FastAPI + static dashboard           Gmail API receiver                          │
│         │                                   │                                      │
│         └──────────── EFS ─────────────────┘                                      │
│                  /opt/segs/data/          (SQLite DBs, audit log)                 │
│                  /opt/segs/gateway/spool/ (quarantine files)                      │
│                                                                                     │
│  AWS Secrets Manager                                                               │
│  segs/prod  (all credentials)                                                     │
│                                                                                     │
│  ECR  pdax/segs  (dashboard + receiver images)                                    │
│                                                                                     │
│  CloudWatch  /segs/dashboard + /segs/receiver  (structured logs)                  │
│                                                                                     │
│  EventBridge + Lambda  segs-renew-watches  (daily Gmail watch renewal fallback)   │
└─────────────────────────────────────────────────────────────────────────────────────┘

                      ┌──────── Google Cloud ───────────┐
                      │  Gmail (Google Workspace)        │
                      │  Pub/Sub topic: segs-gmail       │
                      │  Push subscription → ALB/pubsub  │
                      └─────────────────────────────────┘
```

---

## 10-stage analysis pipeline

The pipeline lives in `app/pipeline/`. Each stage is a standalone function that receives the parsed message and returns a list of `Finding` objects. The aggregator collects all findings, applies weights from `rules/weights.yaml`, and produces a final verdict.

| Stage | Module | Key checks |
|-------|--------|-----------|
| 1 · Headers | `stage_headers.py` | SPF/DKIM/DMARC alignment, Return-Path ≠ From, Reply-To divergence, Message-ID entropy/format, X-Mailer fingerprints |
| 2 · Sender | `stage_sender.py` | Homoglyph domain detection, Levenshtein edit distance against `rules/trusted_domains.txt`, VIP name spoofing (CEO/CFO impersonation), freemail with executive name |
| 3 · URLs | `stage_urls.py` | Anchor text / href mismatch, lookalike URLs in body, risky TLDs (`rules/risky_tlds.txt`), IP-literal links, redirect chain length, mismatched brand domains |
| 4 · Attachments | `stage_attachments.py` | Extension ban list (`rules/banned_extensions.txt`), HTML form credential harvesting patterns, SHA256 hash extraction for VirusTotal lookup |
| 5 · Content AI | `stage_content_ai.py` | GLM (Zhipu/GLM via Vertex AI) or fallback models; prompts: urgency/pressure analysis, BEC financial redirect patterns, wire transfer language, prompt-injection detection |
| 6 · Brand/Visual | `stage_brand.py` | Trusted-service abuse (TestFlight, DocuSign, WeTransfer, Box), service-abuse deception structure heuristics, sender/content mismatch |
| 7 · Threat Intel | `stage_intel.py` | VirusTotal URL and file hash lookup, AbuseIPDB IP confidence score, cached results to avoid rate-limit hits |
| 8 · IOC Correlation | `stage_ioc.py` | Cross-message domain / IP / hash correlation against `data/ioc_cache.db`; signals repeated IOCs from prior incidents |
| 9 · Verdict | `stage_verdict.py` | Weighted score → CLEAN / LOW / SUSPICIOUS / MALICIOUS, hard-override rules from `rules/disposition.yaml`, optional LLM triage assist (`SEG_LLM_TRIAGE=1`) |
| 10 · Report | `stage_report.py` | Slack alert (formatted block kit), SOC dashboard feed write, quarantine notification email to recipient |

### Scoring

Each finding carries a `weight` from `rules/weights.yaml`. Weights are additive. The final score maps to verdicts:

| Score | Verdict |
|-------|---------|
| 0–2 | CLEAN |
| 3–4 | LOW |
| 5–7 | SUSPICIOUS |
| ≥ 8 | MALICIOUS |

Hard overrides in `rules/disposition.yaml` can force any verdict regardless of score (e.g., VirusTotal MALICIOUS always forces MALICIOUS verdict; SPF hard fail on a VIP-spoofed sender directly escalates to MALICIOUS).

---

## Data stores

| File | Format | Contents |
|------|--------|----------|
| `data/users.db` | SQLite | Dashboard user accounts (hashed passwords, roles, MFA state) |
| `data/events.db` | SQLite | Email feed (verdicts, findings, timestamps, source metadata) |
| `data/ioc_cache.db` | SQLite | IOC correlation cache (domains, IPs, hashes, expiry) |
| `data/activity_audit.jsonl` | JSONL | Immutable admin action log (login, release, block, settings change) |
| `gateway/spool/quarantine/` | Directory | Quarantined emails (message.eml + meta.json per message) |
| `gateway/spool/released/` | Directory | Released emails (audit trail) |
| `gateway/spool/rejected/` | Directory | Confirmed-blocked emails |

All data files are excluded from the Docker image (`.dockerignore`). In production they live on EFS and persist across task restarts.

---

## Configuration hierarchy

Settings are read in this priority order (highest wins):

1. Environment variables (from AWS Secrets Manager via ECS task definition)
2. `rules/` YAML files (loaded at startup, hot-reloaded when `rules/enforcement_mode.yaml` changes)
3. Defaults coded in `app/config.py`

The YAML files in `rules/` are committed to the repository and serve as the default policy. Environment variables override for deployment-specific values (credentials, endpoints, modes).

---

## Enforcement mode state machine

```
     [initial deploy]
           │
           ▼
        shadow ──────── monitor 2+ weeks, tune weights
           │
           │  (FP rate < 0.1%, analyst familiar with dashboard)
           ▼
       quarantine ────── normal operations
           │
           │  (Path B live, SMTP infra ready)
           ▼
        reject ────────── hard reject on MALICIOUS
```

Mode is controlled by `SEG_ENFORCE` in Secrets Manager. Change it and force a new ECS deployment with `bash deploy/update-service.sh` — no code change needed.

---

## Security design decisions

**Why no Bedrock?** GLM (Zhipu/GLM via Vertex AI Model Garden) is already provisioned and the keys are in the existing `.env`. Adding Bedrock would require an IAM policy change, a different API surface, and a second vendor. GLM uses an OpenAI-compatible API so the `openai` Python package handles both.

**Why two ALBs?** Separating the dashboard (internal) from the receiver (public) at the ALB level means the dashboard never has a public IP. Even a misconfigured security group rule cannot expose it.

**Why EFS instead of S3?** The spool and SQLite databases require POSIX filesystem semantics (file locking, directory operations). S3 does not support these. EFS adds ~1ms latency which is acceptable for email analysis.

**Why no WAF on the dashboard ALB?** The dashboard is VPN-only — the security group allows only the JumpCloud VPN CIDR. WAF would add cost with no additional security boundary.

**Why WAF on the receiver ALB?** Google Cloud publishes 997+ IP ranges for Pub/Sub. AWS security groups are capped at 60 inbound rules per group. WAF IP sets handle arbitrary-size CIDR lists.
