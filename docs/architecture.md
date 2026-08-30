# SEGS — Architecture

## Overview

SEGS (Secure Email Gateway Suite) is a multi-stage threat detection platform that inspects inbound email for PDAX's Google Workspace environment. The core pipeline is transport-agnostic: it receives a raw `.eml` message and returns a structured verdict. Workers fetch mail and write analysis to Postgres (Aurora) in production, or SQLite when `SEG_DATABASE_URL` is unset. The backend API reads those tables. There is no `gateway/` package and no Path B SMTP hold consumer.

---

## Package layout (FastAPI + MVVM)

Classic MVVM is a UI pattern. Mapped onto this service it means:

| MVVM | Here | Role |
|------|------|------|
| **View** | `backend/api/routers/` | HTTP only: auth, status codes, query params. No scoring. |
| **ViewModel** | `backend/api/feed_builder.py`, sender-profile / workers payloads | Assemble console JSON from stores. Advisory, not verdicts. |
| **Model** | `workers/pipeline/` | Detection stages, runner, verdict. `verdict.py` owns CLEAN/LOW/SUSPICIOUS/MALICIOUS. |
| **Persistence** | `backend/stores/`, `backend/models.py` | Shared types. Postgres when `SEG_DATABASE_URL` is set; SQLite for pytest. |
| **Jobs** | `workers/*.py` | Fetch mail, run pipeline stages, write stores. SQS in production. |

Gmail I/O lives in `workers/gmail.py`. Each worker is `python -m workers <name>` (one Docker container). `workers.receiver:app` remains an optional all-in-one process for the current ECS task. Do not start Gmail poll or LLM from the API process. New jobs go in `workers/<name>.py` with a `main()` and a name in `workers/__main__.py`.

### Job pipeline

Workers write; the API reads. Poll enqueues one static job per copy. The static worker runs every deterministic stage, then content AI. Thread AI runs when every copy in the thread has a per-message assessment. Sender-profile and campaign re-analysis run after that copy's AI (and again after thread AI).

```
Gmail
  → gmail_poll (persist raw .eml to S3 spool/{gmail}/<id>/, pending row)
      → SQS static
      → static worker     headers, sender, URLs, deception, attachments, sandbox, intel
            │
            → SQS content_ai
            → content AI (Vertex cascade: GLM → Gemini Flash → Kimi → DeepSeek)
            │
            → SQS thread_ai (when every copy in the thread has AI)
            → thread AI
            │
            → SQS campaign ∥ SQS profile (in parallel after thread AI)
```

SQS messages hold `{queue_id, bucket, s3_eml, s3_meta}` only — never the `.eml` bytes. Visibility timeout is the lease; a DLQ with `maxReceiveCount=8` replaces SQLite attempts. Timed-out LLM copies retry with backoff. pytest keeps filesystem spool + SQLite queues when AWS env is unset.

The optional all-in-one receiver still exists (`python -m workers receiver`) but production should run **one container per worker**. Set `SEG_INLINE_WORKERS=0` on the receiver task when split workers are deployed so poll/AI do not run twice.

Sandbox stays advisory (never sets `result.verdict`). A real detonator is still a future `SandboxProvider`. RA 10173 / in-house CAPE vs DPO-approved vendor is unchanged.

---

## Gmail integration (read-only)

Google Workspace delivers mail normally. SEGS impersonates configured mailboxes via domain-wide delegation, polls Gmail history, **reads** existing labels, fetches new messages, and runs the worker graph. It does not apply or remove Gmail labels.

```
Sender → Google (SMTP)
              │
              ▼
         Gmail inbox
              │
        SEGS polls Gmail API (outbound, gmail.readonly)
              │
              ▼
    workers.receiver (:8766)
        users.history.list
        users.messages.get
        users.labels.list
              │
        static checks → AI → SQLite
              │
              ▼
            SOC dashboard (API SELECT)
```

**Advantages**: No MX change. Mail is never moved or relabeled in Workspace. Deployment does not need a public Gmail callback URL.

**Limitation**: Mail stays in the inbox. This is the monitoring / read-only phase.

---

## System components

```
┌─────────────────────────────── AWS (ap-southeast-1) ───────────────────────────────┐
│  Dedicated VPC 10.80.0.0/16 (not the account default VPC)                          │
│    public  /24 × 2  ALB + NAT                                                      │
│    private /24 × 2  Fargate API/workers + Aurora                                   │
│                                                                                     │
│  CloudFront + WAF          https://dxxxx.cloudfront.net  (no Route 53 required)    │
│    /*     → S3 (OAC)       web-console                                             │
│    /api*  → HTTP API       OpenAPI body (infra/openapi.yaml) → VPC link → ALB      │
│    /scim* → HTTP API       same origin; SCIM 2.0 at /scim/v2                       │
│                 │                                                                   │
│                 ▼                                                                   │
│  ECS Fargate segs-api (:8765)     1024 CPU / 2048 MiB × 2                          │
│  ECS Fargate workers              split: poll, static, content_ai, …               │
│         │                           content_ai 1024 CPU / 2048 MiB                 │
│         │                           │                                              │
│         └──────── Aurora (private) + S3 mail spool (SSE-KMS) + SQS ──┘
│                  Aurora Postgres      assessments, auth, jobs metadata
│                  S3 spool/{gmail,…}/  message.eml + meta.json
│                  SQS                  static → content_ai → thread_ai → campaign∥profile
│
│  Secrets Manager   segs/{env}/app (operator) + segs/{env}/infra (Terraform)
│  KMS CMK           one key for S3, SQS, Aurora, secrets, CloudWatch Logs
│  ECR  pdax/segs-api + pdax/segs-worker  (immutable, digest-pinned)
│  CloudWatch  /segs/api + /segs/receiver + /segs/worker  (90-day retention)
└─────────────────────────────────────────────────────────────────────────────────────┘

                      ┌──────── Google Workspace ───────┐
                      │  Gmail API (DWD gmail.readonly)  │
                      │  SEGS polls users.history.list   │
                      └─────────────────────────────────┘
```

The HTTP API contract is [docs/openapi.yaml](openapi.yaml). Terraform imports the same operations (with VPC-link integrations) as `infra/openapi.yaml` into API Gateway, so only documented `/api` and `/scim` routes reach the internal ALB. After adding a FastAPI route, regenerate with `python -m backend.api.openapi`. Interactive `/docs` is not served.

---

## 10-stage analysis pipeline

The pipeline lives in `workers/pipeline/`. Each stage is a standalone function that receives the parsed message and returns a list of `Finding` objects. The aggregator collects all findings, applies weights from `backend/policy/detection/weights.yaml`, and produces a final verdict.

| Stage | Module | Key checks |
|-------|--------|-----------|
| 1 · Headers | `stage_headers.py` | SPF/DKIM/DMARC alignment, Return-Path ≠ From, Reply-To divergence, Message-ID entropy/format, X-Mailer fingerprints |
| 2 · Sender | `stage_sender.py` | Homoglyph domain detection, Levenshtein edit distance against protected domains, VIP name spoofing (CEO/CFO impersonation), freemail with executive name |
| 3 · URLs | `stage_urls.py` | Anchor text / href mismatch, lookalike URLs in body, risky TLDs, IP-literal links, redirect chain length, mismatched brand domains |
| 4 · Attachments | `stage_attachments.py` | Extension ban list (`backend/policy/detection/banned_extensions.txt`), HTML form credential harvesting patterns, SHA256 hash extraction for VirusTotal lookup |
| 5 · Content AI | `stage_content_ai.py` | GLM (Zhipu/GLM via Vertex AI) or fallback models; prompts: urgency/pressure analysis, BEC financial redirect patterns, wire transfer language, prompt-injection detection |
| 6 · Brand/Visual | `stage_brand.py` | Trusted-service abuse (TestFlight, DocuSign, WeTransfer, Box), service-abuse deception structure heuristics, sender/content mismatch |
| 7 · Threat Intel | `stage_intel.py` | VirusTotal URL and file hash lookup, AbuseIPDB IP confidence score, cached results to avoid rate-limit hits |
| 8 · IOC Correlation | `stage_ioc.py` | Cross-message domain / IP / hash correlation against `data/ioc_cache.db`; signals repeated IOCs from prior incidents |
| 9 · Verdict | `stage_verdict.py` | Weighted score → CLEAN / LOW / SUSPICIOUS / MALICIOUS, hard-override rules from `backend/policy/detection/disposition.yaml`, optional LLM triage assist (`SEG_LLM_TRIAGE=1`) |
| 10 · Report | `stage_report.py` | Slack alert (formatted block kit), SOC dashboard feed write, quarantine notification email to recipient |

### Scoring

Each finding carries a `weight` from `backend/policy/detection/weights.yaml`. Weights are additive. The final score maps to verdicts:

| Score | Verdict |
|-------|---------|
| 0–2 | CLEAN |
| 3–4 | LOW |
| 5–7 | SUSPICIOUS |
| ≥ 8 | MALICIOUS |

Hard overrides in `backend/policy/detection/disposition.yaml` can force any verdict regardless of score (e.g., VirusTotal MALICIOUS always forces MALICIOUS verdict; SPF hard fail on a VIP-spoofed sender directly escalates to MALICIOUS).

---

## Data stores

| Store | Backend | Contents |
|------|---------|----------|
| assessments / auth / jobs / followup / campaign / correlation | Postgres (`SEG_DATABASE_URL`) or SQLite files under `data/` | Copy rows, users, queues, campaigns, sender history |
| `data/activity_audit.jsonl` | JSONL | Immutable admin action log |
| S3 `spool/gmail/<queue_id>/` | SSE-KMS objects | Live Gmail copies (`message.eml` + `meta.json`) |
| S3 `spool/quarantine\|released\|rejected/` | SSE-KMS objects | Enforcement buckets |
| Filesystem `email/spool/` | Directory | Same layout when `SEG_S3_BUCKET` is unset (pytest / local) |

SQS payloads never contain `.eml` bodies. CloudWatch Logs retention is 90 days.

---

## Configuration hierarchy

Settings are read in this priority order (highest wins):

1. Environment variables (from AWS Secrets Manager via ECS task definition)
2. `backend/policy/` YAML files (loaded at startup, hot-reloaded when `backend/policy/runtime/enforcement_mode.yaml` changes)
3. Defaults coded in `backend/config.py`

The YAML files in `backend/policy/` are committed with the package and serve as the default policy. Environment variables override for deployment-specific values (credentials, endpoints, modes).

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

**Why two ALBs?** The analyst API can stay off the public internet. The Gmail receiver only needs outbound HTTPS to Google and does not need a public ALB.

**Why S3 + SQS + Aurora?** `.eml` bodies need object storage with SSE-KMS; work items are small JSON keys that belong on SQS; relational state belongs in Aurora. pytest still uses filesystem + SQLite when those env vars are unset.

**Why no WAF on the dashboard ALB?** The dashboard is VPN-only — the security group allows only the JumpCloud VPN CIDR. WAF would add cost with no additional security boundary.
