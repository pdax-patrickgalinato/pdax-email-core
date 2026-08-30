# SEGS — Configuration Reference

Typed defaults live in `backend/config.py` (`get_settings()`). `.env` is sourced by
`start_server.sh` / Docker into the process environment — Settings does not
auto-load the file (so pytest stays isolated).

All environment variables for production deployments are stored in AWS Secrets Manager secret `segs/prod`. The ECS task definitions inject them at container start. For local development, copy `.env.example` to `.env` and fill in your values.

---

## Core

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `SEG_ENFORCE` | `shadow` | Yes | Enforcement mode: `shadow` (log only), `quarantine` (hold SUSPICIOUS+MALICIOUS), `reject` (quarantine + SMTP 550 on MALICIOUS, Path B only) |
| `SEG_QUARANTINE_ROOT` | `email/spool` | Filesystem spool when `SEG_S3_BUCKET` is empty. |
| `SEG_COOKIE_SECURE` | `0` | Yes (prod) | Set to `1` when running behind HTTPS (CloudFront). Enables `Secure` cookie flag + HSTS header. |
| `SEG_SERVE_SPA` | `1` | No | Set to `0` on Fargate. The SOC console is served from S3 + CloudFront; the API only handles `/api/*`. |
| `SEG_SECRET_KEY` | auto-generated | Recommended | Django-style secret key for session signing. Set explicitly to persist sessions across restarts. Generate: `python3 -c "import secrets; print(secrets.token_hex(32))"` |
| `SEG_LANDING_FETCH` | `0` | No | **Keep at `0` in all environments.** This flag made SEGS fetch attacker URLs directly from the SEGS machine — exposing your infrastructure IP, fingerprinting the scanner via the `SEGS-LandingFetch/1.0` user-agent, and leaving an unpatched DNS rebinding SSRF gap. URL intelligence is now handled safely by VirusTotal URL submission (VT's servers fetch the URL, not SEGS) and ClamAV URL signature scanning (local, no outbound connection). See §URL Analysis below. |
| `SEG_RDAP_LOOKUP` | `0` | No | Set to `1` to enable RDAP domain registration date lookup. Penalizes newly registered domains. |
| `SEG_LLM_TRIAGE` | `0` | No | Set to `1` to enable LLM-assisted verdict triage in Stage 9. Adds a second GLM call for borderline scores. |

---

## Gmail API (Path A)

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `SEG_GMAIL_CREDENTIALS` | `credentials.json` | Yes | Path to the GCP service account JSON key file. In containers, `deploy/docker/entrypoint.sh` writes this file from `SEGS_GMAIL_CREDENTIALS_JSON`. |
| `SEGS_GMAIL_CREDENTIALS_JSON` | — | Yes (prod) | Full contents of `credentials.json` as a single-line JSON string. Stored in Secrets Manager; written to `SEG_GMAIL_CREDENTIALS` path at container start. Never put this in the Docker image. |
| `SEG_GMAIL_USERS` | — | Yes | Comma-separated Workspace mailboxes to impersonate via domain-wide delegation. Non-`SEG_GMAIL_DOMAIN` addresses are ignored. Example: `security@pdax.ph,pat@pdax.ph`. |
| `SEG_GMAIL_DOMAIN` | `pdax.ph` | No | Primary Workspace domain. The poller only impersonates `@` this domain (fan-out will not add fireblocks.com / google.com inboxes). |
| `SEG_GMAIL_POLL_SECONDS` | `30` | No | How often the receiver polls Gmail history. First poll snapshots history and does not backfill. |
| `SEG_PROFILE_WORKER` | `1` | No | Background ingest of CLEAN/LOW sender profiles from stored spool copies (no LLM). Production drains the profile SQS queue. Set `0` to disable. |
| `SEG_PROFILE_WORKERS` | `4` | No | In-process profile-ingest threads per sender container. Production sets `8`. |
| `SEG_CAMPAIGN_WORKER` | `1` | No | Background clustering of phishing-campaign patterns (shared landing URLs, attachment hashes, subject/body templates) from stored spool copies. Writes `data/campaigns.sqlite3`. Reference-only — does not change the composite score. Set `0` to disable. |
| `SEG_CAMPAIGN_WORKER_SECONDS` | `90` | No | How often the campaign worker rescans spool and reclusters. |
| `SEG_INCONCLUSIVE_RETRY` | `1` | No | Background re-queue of timed-out LLM assessments. Must run in the Gmail receiver (that process owns the LLM queue). Exponential backoff, cap `SEG_INCONCLUSIVE_RETRY_MAX`. Oldest timed-out copies are retried first. Set `0` to disable. |
| `SEG_INCONCLUSIVE_RETRY_SECONDS` | `30` | No | How often the retry worker considers timed-out copies. |
| `SEG_INCONCLUSIVE_RETRY_BATCH` | `25` | No | Max timed-out copies to re-queue per retry cycle. The receiver also fills leftover LLM worker slots from the oldest missing assessments on each poll so a restart does not strand the backlog. |
| `SEG_SENDER_RISK_WORKER` | `1` | No | API-process worker that writes an advisory sender-identity risk (sent/received volume, reciprocity, targeting). Uses the configured content provider for the narrative when it is not `heuristic`. Does not change message verdicts. |
| `SEG_SENDER_RISK_SECONDS` | `60` | No | How often the sender-risk worker considers stale profiles. |
| `SEG_SENDER_RISK_BATCH` | `5` | No | Max senders to (re)assess per `sender_risk_cycle` (tests / sqlite). Live workers assess one address at a time. |
| `SEG_SENDER_RISK_WORKERS` | `2` | No | In-process sender-identity LLM threads per sender container. Production sets `4`. |
| `SEG_LLM_ASSESS_TIMEOUT_SECONDS` | `120` | No | Full budget for one Gmail LLM attempt, starting when a worker picks up the copy (not when it was first queued). The feed shows INCONCLUSIVE if no summary exists after this window. |
| `SEG_LLM_MODEL_TIMEOUT_SECONDS` | `25` | No | Per-Vertex-slot HTTP timeout inside the GLM fallback chain. Kept shorter than the attempt budget so a hung slot does not starve GLM / Kimi / Gemini. Capped at attempt budget minus 20s. |
| `SEG_STATIC_WORKERS` | `2` | No | In-process static-check threads per static container. |
| `SEG_INTEL_WORKERS` | `1` | No | Unused for a separate queue — intel runs inside the static worker. |
| `SEG_JOB_LEASE_SECONDS` | `360` | No | SQLite claim lease when SQS URLs are unset. SQS uses queue visibility timeout instead. |
| `SEG_RECEIVER_HEALTH_URL` | `http://127.0.0.1:8766/health` | No | Where the API probes the all-in-one receiver. Unused for split workers. |
| `SEG_WORKER_HEALTH_BASE_URL` | empty locally; internal ALB in ECS | No | API probes `{base}/{name}/health` for each split worker (gmail_poll, static, …). Terraform sets this to the internal workers ALB. |
| `SEG_CONTENT_AI_WORKERS` | `4` | No | In-process Vertex assessment threads per content_ai container. |
| `SEG_THREAD_AI_WORKERS` | `1` | No | In-process thread-transcript AI threads per thread_ai container. |
| `SEG_JOB_LEASE_SECONDS` | `360` | No | SQLite claim lease when SQS URLs are unset. SQS uses queue visibility timeout instead. |
| `SEG_JOB_MAX_ATTEMPTS` | `8` | No | After this many failed claims a job is dead-lettered and the copy is marked `dead_letter` instead of being retried forever. |
| `SEG_GMAIL_FETCH_WORKERS` | `4` | No | Parallel `messages.get` calls inside one mailbox during a poll cycle. |
| `SEG_LLM_BACKFILL_LIMIT` | `200` | No | Max missing-LLM copies to re-queue per backfill pass (SQL first, then spool). |
| `SEG_INLINE_WORKERS` | `1` | No | Set `0` on the all-in-one receiver when poll/static/AI run as separate containers so they are not started twice. |
| `SEG_WORKER_HEALTH_PORT` | `8766` | No | Listen port for each split worker's `/health` server. |
| `SEG_CORRELATION_STORE` | `0` locally / `1` in Docker | No | Persist sender-history / request-class observations during `run_pipeline`. Docker and ECS set this to `1`. |
| `SEG_GMAIL_TOPIC` | — | No | Unused in poll mode (legacy Pub/Sub push). |
| `SEG_PUBSUB_TOKEN` | — | No | Unused in poll mode (legacy Pub/Sub push). |

---

## Content AI (GLM via Vertex AI)

SEGS uses Vertex AI Model Garden (OpenAI-compatible MaaS) for content analysis. The cascade tries **GLM 5.2 first**, then Gemini Flash, then Kimi, with DeepSeek R1 last (slow reasoning model). The `openai` Python package is used.

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `SEG_CONTENT_PROVIDER` | `glm` | Yes | AI provider: `glm` (Zhipu/GLM), `claude` (Claude via Bedrock), `disabled` |
| `SEG_GLM_MODEL_ID` | `deepseek-ai/deepseek-r1-0528-maas` | Yes | Primary Vertex MaaS model ID. Default is DeepSeek R1. |
| `SEG_GLM_API_KEY` | — | Yes | GLM API key. Leave empty if using service account authentication via `SEG_GLM_CREDENTIALS_PATH`. |
| `SEG_GLM_PROJECT_ID` | — | Yes | GCP project ID hosting the GLM deployment in Vertex AI Model Garden. |
| `SEG_GLM_ENDPOINT` | auto | No | Custom endpoint URL. Defaults to the standard Vertex AI Model Garden endpoint for the project. |
| `SEG_GLM_LOCATION` | `us-central1` | Yes | Vertex location for the primary model. DeepSeek R1 requires `us-central1`. |
| `SEG_GLM_FALLBACK1_MODEL_ID` | `zai-org/glm-5.2-maas` | No | First fallback model ID if the primary model is unavailable. |
| `SEG_GLM_FALLBACK1_LOCATION` | `global` | No | Region for fallback 1. |
| `SEG_GLM_FALLBACK2_MODEL_ID` | — | No | Second fallback model ID. |
| `SEG_GLM_FALLBACK2_LOCATION` | — | No | Region for fallback 2 model (if different from primary). |
| `SEG_GLM_FALLBACK3_MODEL_ID` | — | No | Third fallback model ID. |
| `SEG_GLM_FALLBACK3_LOCATION` | — | No | Region for fallback 3 model. |
| `SEG_GLM_CREDENTIALS_PATH` | — | No | Path to a Google service account JSON file for Vertex AI authentication (alternative to API key). |

---

## Threat Intelligence

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `SEG_INTEL_CLIENT` | `disabled` | No | Intel provider: `vt_abuseipdb` (both), `virustotal`, `abuseipdb`, `disabled` |
| `SEG_VT_API_KEY` | — | If intel enabled | VirusTotal API key. Free tier: 4 requests/minute, 500 lookups/day. Hashes and URLs are looked up; results cached in `data/ioc_cache.db`. |
| `SEG_ABUSEIPDB_API_KEY` | — | If intel enabled | AbuseIPDB API key. Used to check sender IP reputation. |

### VT / AbuseIPDB quota exhaustion

When the daily lookup quota for VirusTotal or AbuseIPDB is exhausted (HTTP 429), SEGS sets a **process-level backoff flag** that remains active for one hour. During that window, every subsequent email scan skips intel lookups for the exhausted provider rather than sleeping 15 s per indicator and eventually hitting 429 again. This prevents the 120 s worst-case timeout spike (8 indicators × 15 s throttle) from recurring on every email once the daily cap is hit.

**What users see when quota is exhausted:**
- A yellow warning banner in the Analyze tab: *"⚠️ API quota limit reached: VirusTotal / AbuseIPDB …"*
- A blockquote in the Full Markdown Report under the SEGS Gateway Analysis section
- A `quota_flags` array in the `/api/analyze/eml` JSON response: `["quota_exhausted_vt"]` and/or `["quota_exhausted_abuseipdb"]`

The flag resets automatically after one hour (or on process restart). Results for emails scanned during the quota window may be **incomplete** — indicators not checked will be re-evaluated on the next email scan once the quota resets.

**Operational guidance:**
- If quota exhaustion occurs frequently, upgrade to a paid VT / AbuseIPDB tier.
- The `SEG_VT_MAX_INDICATORS_PER_EMAIL` tuning variable (see *Tuning / Performance* section below) caps how many indicators are looked up per email, slowing the rate of quota consumption.

---

## S3 / Wazuh SIEM Integration

SEGS ships audit logs to S3 so that Wazuh (or any S3-compatible SIEM) can ingest them. The shipper runs as a background daemon thread inside the dashboard ECS task. It is **disabled by default** — no-op when `SEG_S3_BUCKET` is not set.

| Variable | Default | Description |
|----------|---------|-------------|
| `SEG_S3_BUCKET` | `""` | Mail spool bucket (SSE-KMS). Also used by the Wazuh log shipper (`logs/` prefix). Empty = filesystem spool and shipper off. |
| `SEG_KMS_KEY_ARN` | `""` | Project CMK ARN for S3 PutObject. Terraform infra secret. |
| `SEG_DATABASE_URL` | `""` | Postgres URL. Empty = SQLite files under `data/`. |
| `SEG_SQS_STATIC_URL` | `""` | Static-check queue. Empty = SQLite `workers/jobs.py`. |
| `SEG_S3_PREFIX` | `segs/logs` | S3 key prefix. Keys follow the pattern `{prefix}/{source}/{YYYY}/{MM}/{DD}/{HHMMSS}-{uuid}.jsonl.gz`. |
| `SEG_S3_REGION` | `ap-southeast-1` | AWS region for the S3 client. Defaults to `AWS_REGION` env var, then `ap-southeast-1`. |
| `SEG_S3_SHIP_INTERVAL` | `60` | Flush interval in seconds. The shipper wakes up every N seconds, reads new log lines since the last checkpoint, and uploads a gzip-compressed JSONL batch to S3. |

**Log sources shipped:**

| Source name | Local file | Description |
|-------------|-----------|-------------|
| `activity_audit` | `data/activity_audit.jsonl` | Admin actions: login, release, block, user changes, settings saves |
| `shadow_enforcement` | `email/spool/shadow_logs/shadow_enforcement.jsonl` | Shadow-mode enforcement decisions (emails that would have been quarantined/rejected) |

Each record is tagged with `"wazuh": true` before upload so the Wazuh pipeline can identify SEGS-originating events. The dashboard "Wazuh alerts only" feed filter reads this field.

**IAM permissions required** (ECS task role — already granted by `segs-task-role`):
```json
{
  "Effect": "Allow",
  "Action": ["s3:PutObject"],
  "Resource": "arn:aws:iam::ACCOUNT:s3:::BUCKET/segs/logs/*"
}
```

**Checkpoint file**: `data/wazuh_shipper_offsets.json` — persists byte offsets across restarts so no records are re-shipped or skipped. Written atomically via `.tmp` + rename.

---

## Tuning / Performance

These variables control timeout and throughput budgets. The defaults are calibrated for the free-tier VT rate limit (4 req/min) with up to 8 indicators per email. Raise the timeouts if you see 504 responses on EML uploads; lower `SEG_VT_MAX_INDICATORS_PER_EMAIL` to reduce VT quota consumption.

| Variable | Default | Description |
|----------|---------|-------------|
| `SEG_ANALYZE_TIMEOUT_SECONDS` | `300` | Per-phase timeout (seconds) for the EML Analyzer (`POST /api/analyze/eml`). Covers both the pipeline run and the GLM deep-analysis call separately — each phase gets this budget independently. Raise to `600` if large attachments or slow OSINT enrichment trigger 504 errors. |
| `SEG_EMAIL_SCAN_TIMEOUT_SECONDS` | `300` | Timeout for live incoming Gmail email scans processed by the receiver. Applies to the full pipeline including GLM content analysis and VT intel lookups. |
| `SEG_VT_MAX_INDICATORS_PER_EMAIL` | `8` | Maximum number of indicators (hashes + URLs + IPs) submitted to VirusTotal per email. Caps worst-case VT throttle at `8 × 15 s = 120 s` on the free tier. Raise if you need deeper coverage and have a paid API tier; lower to `3–4` to preserve daily quota on high-volume deployments. |
| `SEG_VT_TIME_BUDGET_SECONDS` | `90` | Hard wall-clock cap on the entire VT + AbuseIPDB intel stage per email. Once elapsed, remaining uncached indicators are skipped and the pipeline continues — guarantees the intel stage never stalls the pipeline regardless of indicator count or API latency. The count budget (`SEG_VT_MAX_INDICATORS_PER_EMAIL`) and this time budget are enforced together; whichever is hit first wins. Raise to `180` with a paid VT tier. |

---

## SMTP Notifications

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `SEG_NOTIFY_SMTP_HOST` | `smtp.gmail.com` | No | SMTP server hostname |
| `SEG_NOTIFY_SMTP_PORT` | `587` | No | SMTP port (587 = STARTTLS) |
| `SEG_NOTIFY_SMTP_USER` | — | No | SMTP authentication username (typically the `segs-alerts@pdax.ph` address) |
| `SEGS_NOTIFY_SMTP_PASS` | — | If SMTP enabled | SMTP App Password. **Never stored in YAML files or Docker images.** Read exclusively from this environment variable. |
| `SEG_NOTIFY_FROM` | — | No | From address for quarantine notification emails. Example: `segs-alerts@pdax.ph` |
| `SEG_NOTIFY_TO` | — | No | Default To address for admin notifications. Individual quarantine alerts go to the email recipient. |

---

## Organization

Configured in `backend/policy/identity/org.yaml` (committed) plus environment overrides:

| Variable | Default | Description |
|----------|---------|-------------|
| `SEG_ORG_NAME` | From `backend/policy/identity/org.yaml` | Organization display name shown in alerts and dashboard header |
| `SEG_ORG_DOMAIN` | From `backend/policy/identity/org.yaml` | Primary email domain (used in sender analysis) |

`backend/policy/identity/org.yaml` current values:
```yaml
organization:
  display_name: "PDAX"
  domain: "pdax.ph"
  regulator_context: "a BSP-regulated crypto exchange"
  vip_names:
    - CEO
    - CFO
    - CTO
    - President
    - "Chief Executive"
    - "Chief Financial"
```

---

## YAML configuration files

These files live in `backend/policy/` (grouped by role) and ship with the package. They define the default detection policy and can be tuned without code changes. Changes take effect on the next pipeline run (no restart needed for most files; `enforcement_mode.yaml` is hot-reloaded).

| File | Purpose |
|------|---------|
| `backend/policy/identity/org.yaml` | Organization display name and regulator context |
| `backend/policy/identity/protected_domains.txt` | Domains attackers might imitate |
| `backend/policy/identity/vip_names.txt` | Names used in impersonation attacks |
| `backend/policy/identity/impersonation_brands.txt` | Brand tokens for trusted-channel abuse |
| `backend/policy/identity/freemail_domains.txt` | Consumer mailbox providers |
| `backend/policy/identity/trusted_platforms.yaml` | Authentic platforms (Apple, Google, …) vs foreign brand lure |
| `backend/policy/detection/weights.yaml` | Per-stage scoring weights and verdict thresholds |
| `backend/policy/detection/policy.yaml` | TMES-parity category enable/suppress toggles |
| `backend/policy/detection/disposition.yaml` | Verdict → gateway action mapping |
| `backend/policy/detection/detection_rules.yaml` | Named flag-matching rules |
| `backend/policy/detection/banned_extensions.txt` | Attachment extensions always flagged |
| `backend/policy/runtime/enforcement_mode.yaml` | Live enforce-mode override (dashboard-writable) |
| `backend/policy/runtime/allowlist.yaml` / `blocklist.yaml` | Sender hard overrides |
| `backend/policy/runtime/slack_config.yaml` | Slack alert webhook |
| `backend/policy/runtime/notify_config.yaml` | Quarantine recipient notification |

### Tuning `backend/policy/detection/weights.yaml`

Each finding type has a weight in [0, 10]. The total score is the sum of all triggered findings' weights. Thresholds (by default: 3 = LOW, 5 = SUSPICIOUS, 8 = MALICIOUS) are in `backend/policy/detection/disposition.yaml`.

Finding type naming conventions:
- `header_*` — Stage 1 (headers)
- `sender_*` — Stage 2 (sender identity)
- `url_*` — Stage 3 (URLs)
- `attach_*` — Stage 4 (attachments)
- `content_*` — Stage 5 (content AI)
- `brand_*` — Stage 6 (brand abuse)
- `intel_*` — Stage 7 (threat intel)
- `ioc_*` — Stage 8 (IOC correlation)

### Hard overrides in `backend/policy/detection/disposition.yaml`

Findings listed under `force_malicious` always set the verdict to MALICIOUS regardless of the total score. Current overrides:
- `intel_vt_malicious` — VirusTotal confirmed malicious attachment
- `sender_dmarc_hard_fail_vip` — DMARC hard fail + VIP name spoof
- `attach_macro_active_content` — Office macro with active content execution

Findings under `force_suspicious` similarly force SUSPICIOUS minimum.

---

## AWS-specific (deployment only)

These are not SEGS application variables — they're used by the deployment scripts:

| Variable | Used by | Description |
|----------|---------|-------------|
| `AWS_ACCOUNT_ID` | `deploy/push-images.sh`, `deploy/update-service.sh` | 12-digit AWS account ID |
| `AWS_REGION` | All deploy scripts | Deployment region (default: `ap-southeast-1`) |
| `ECR_REPO` | `deploy/push-images.sh` | ECR repository name (default: `pdax/segs`) |
| `AWS_REGION` | region for SQS/S3/KMS |
| `ECS_CLUSTER` | `deploy/update-service.sh` | ECS cluster name (default: `segs`) |

---

## Defense in Depth — URL Analysis

SEGS analyses every URL extracted from an email through **two safe layers**. Neither layer makes an outbound HTTP connection from the SEGS machine — there is no direct browsing of attacker links.

> **Security note:** `SEG_LANDING_FETCH` is **permanently disabled** (`0`) in all environments. It previously made direct HTTP connections from the SEGS machine to attacker URLs, exposing the infrastructure IP, fingerprinting the scanner, and leaving an unpatched DNS rebinding SSRF gap. The two layers below provide equivalent or better coverage without those risks.

| Layer | How it works | Who connects to the URL | Requires |
|-------|-------------|------------------------|---------|
| **① VirusTotal URL submission** (`workers/pipeline/intel.py`, Stage 7) | URL submitted to VT's API → VT's own infrastructure fetches and scans it → reputation score returned. Known-bad URLs → `intel_url:` flag → `threat_intel_hit` hard override (MALICIOUS, score 100). New URLs are submitted for background scanning and return results on the next check. | **VT's servers — not SEGS** | `SEG_INTEL_CLIENT=vt_abuseipdb` + `SEG_VT_API_KEY` |
| **② ClamAV URL scan** (`workers/pipeline/intel.py`, Stage 7) | URL string bytes passed to local `clamd` via `scan_stream()`. ClamAV checks against its URL-based signature database: URLhaus, phishing patterns, malware-distribution indicators. A hit → `intel_url_clam:` flag → `threat_intel_hit` hard override (MALICIOUS, score 100). | **Nobody — local signature lookup, zero outbound** | `SEG_SANDBOX_PROVIDER=clamav` + `pyclamd` + running `clamd` |

Both layers degrade gracefully: if VT quota is exhausted the URL check skips; if clamd is unreachable the URL string scan skips. Other pipeline stages continue normally.

---

## Defense in Depth — Attachment Inspection Layers

SEGS inspects attachments through **four independent layers**. Each layer compensates for the blind spots of the others. They always run in this order:

| Layer | What it catches | Always runs? | Requires |
|-------|----------------|--------------|---------|
| **① Static forensics** (`backend/attachment_forensics.py`) | File-type spoofing (magic-byte vs extension), zip-bombs, Office macros (OLE + OOXML), PDF active content tokens, HTML credential forms, executable content, byte entropy | Yes — unconditional, offline, stdlib-only | Nothing |
| **② ClamAV AV scan** (`workers/pipeline/sandbox.py`) | Known malware signatures, ransomware families, known phishing kits, known malicious macros — the entire ClamAV signature database | No — opt-in; activates when `SEG_SANDBOX_PROVIDER=clamav` | `pyclamd` + running `clamd` daemon |
| **③ VT hash reputation** (`workers/pipeline/intel.py`, Stage 7) | Files already seen and confirmed malicious by the global VT community | No — requires `SEG_INTEL_CLIENT=vt_abuseipdb` + `SEG_VT_API_KEY` | VirusTotal API key |
| **④ LLM content reasoning** (`workers/pipeline/content_ai.py`, Stage 5) | Novel social engineering in VBA macro code strings, HTML phishing page lure text, context mismatches between email body and attachment content — what signatures cannot reason about | No — requires a real LLM provider (GLM, Bedrock, Gemini, Ollama) | LLM provider + API key |

**ClamAV is purely additive.** Disabling or misconfiguring it does not affect the other layers. If `clamd` is unreachable, the pipeline logs `sandbox_clam_unavailable` and continues normally — the existing static forensics verdict stands.

### ClamAV configuration

Setting `SEG_SANDBOX_PROVIDER=clamav` activates ClamAV for **both** attachment scanning and URL string scanning simultaneously — one switch enables both layers.

| Variable | Default | Description |
|----------|---------|-------------|
| `SEG_SANDBOX_PROVIDER` | `null` | Set to `clamav` to activate ClamAV scanning for attachments **and** URL strings. Any other value keeps the no-op stub. |
| `SEG_CLAMD_HOST` | `localhost` | clamd daemon hostname (used when `SEG_CLAMD_SOCKET` is not set). |
| `SEG_CLAMD_PORT` | `3310` | clamd TCP port. |
| `SEG_CLAMD_SOCKET` | — | Unix socket path (e.g. `/var/run/clamav/clamd.ctl`). When set, takes priority over host:port. Preferred for same-host/sidecar deployments. |

**Activation checklist:**
1. Install `pyclamd`: add `pyclamd` to `requirements.txt` (uncomment the stub) and rebuild the container.
2. Ensure `clamd` is running and reachable from the SEGS container (sidecar or shared service).
3. Set `SEG_SANDBOX_PROVIDER=clamav` in AWS Secrets Manager (`segs/prod`).
4. Verify attachments: upload an EICAR test EML via the Analyzer — the report should show `🔴 MALICIOUS — Eicar-Signature` in the Attachment Detail table and a `clam_malicious` hard override.
5. Verify URL scanning: upload an EML containing a URL from the URLhaus blocklist — the intel stage should show an `intel_url_clam:` flag and a `threat_intel_hit` hard override.

The `virtual_analyzer` policy category in `backend/policy/detection/policy.yaml` gates whether a ClamAV attachment hit fires the hard override. It defaults to `enabled: true`. To suppress ClamAV attachment scoring without removing the env var, set `virtual_analyzer: enabled: false` in `backend/policy/detection/policy.yaml`. ClamAV URL hits are gated by the `correlated_intelligence` category instead (same gate as VT URL hits).

---

## JumpCloud SSO (planned future — disabled by default)

The platform is SSO-ready. The `SSOMiddleware` in `backend/api/security.py` reads `SEG_SSO_PROVIDER` at startup. When empty (the default), the middleware is a no-op and the platform uses its own session-cookie login. Set to `alb_oidc` to activate the JumpCloud SSO gate with no code changes.

| Variable | Description |
|----------|-------------|
| `SEG_SSO_PROVIDER` | Set to `alb_oidc` to require an AWS ALB OIDC token (JumpCloud). Empty = disabled (default). |
| `SEG_OIDC_CLIENT_ID` | JumpCloud OIDC app Client ID — the ALB listener uses this directly; stored here for documentation. |
| `SEG_OIDC_CLIENT_SECRET` | JumpCloud OIDC app Client Secret — same note. |
| `SEG_OIDC_ISSUER` | JumpCloud OIDC discovery base URL (`https://oauth.id.jumpcloud.com`). |

All four are stored as comments in `.env.example` and become active entries in `segs/prod` Secrets Manager when SSO is enabled. See `docs/jumpcloud-sso.md` for the full activation walkthrough.

---

## Environment variable load order

For local development (`.env` file):
```
.env → backend/config.py defaults
```

For production (ECS Fargate):
```
AWS Secrets Manager segs/prod → ECS task environment → deploy/docker/entrypoint.sh (writes credentials.json) → backend/config.py defaults
```

The `deploy/docker/entrypoint.sh` script runs at container start and:
1. Reads `SEGS_GMAIL_CREDENTIALS_JSON` from the environment
2. Writes it to `$SEG_GMAIL_CREDENTIALS` (default: `/opt/segs/credentials.json`)
3. Sets `chmod 600` on the file
4. Starts uvicorn

This means `credentials.json` is never in the container image and never persists between deployments.
