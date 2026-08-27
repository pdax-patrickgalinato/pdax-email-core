# SEGS — Configuration Reference

All environment variables for production deployments are stored in AWS Secrets Manager secret `segs/prod`. The ECS task definitions inject them at container start. For local development, copy `.env.example` to `.env` and fill in your values.

---

## Core

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `SEG_ENFORCE` | `shadow` | Yes | Enforcement mode: `shadow` (log only), `quarantine` (hold SUSPICIOUS+MALICIOUS), `reject` (quarantine + SMTP 550 on MALICIOUS, Path B only) |
| `SEG_QUARANTINE_ROOT` | `gateway/spool` | Yes | Absolute path to the quarantine spool directory. Set to `/opt/segs/gateway/spool` in containers. |
| `SEG_COOKIE_SECURE` | `0` | Yes (prod) | Set to `1` when running behind HTTPS (ALB). Enables `Secure` cookie flag + HSTS header. |
| `SEG_SECRET_KEY` | auto-generated | Recommended | Django-style secret key for session signing. Set explicitly to persist sessions across restarts. Generate: `python3 -c "import secrets; print(secrets.token_hex(32))"` |
| `SEG_LANDING_FETCH` | `0` | No | Set to `1` to fetch landing pages behind URLs (redirect chain resolution). Adds latency but improves URL analysis accuracy. |
| `SEG_RDAP_LOOKUP` | `0` | No | Set to `1` to enable RDAP domain registration date lookup. Penalizes newly registered domains. |
| `SEG_LLM_TRIAGE` | `0` | No | Set to `1` to enable LLM-assisted verdict triage in Stage 9. Adds a second GLM call for borderline scores. |

---

## Gmail API (Path A)

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `SEG_GMAIL_CREDENTIALS` | `credentials.json` | Yes | Path to the GCP service account JSON key file. In containers, `entrypoint.sh` writes this file from `SEGS_GMAIL_CREDENTIALS_JSON`. |
| `SEGS_GMAIL_CREDENTIALS_JSON` | — | Yes (prod) | Full contents of `credentials.json` as a single-line JSON string. Stored in Secrets Manager; written to `SEG_GMAIL_CREDENTIALS` path at container start. Never put this in the Docker image. |
| `SEG_GMAIL_TOPIC` | — | Yes | Full Pub/Sub topic name. Format: `projects/<project-id>/topics/<topic-name>`. Example: `projects/pdax-segs-123/topics/segs-gmail`. |
| `SEG_GMAIL_USERS` | — | Yes | Comma-separated list of mailboxes to monitor. Example: `security@pdax.ph,pat@pdax.ph`. The service account must have DWD authorization to access each mailbox. |
| `SEG_GMAIL_DOMAIN` | — | No | Primary domain for context (e.g. `pdax.ph`). Used to categorize internal vs external senders. |
| `SEG_PUBSUB_TOKEN` | — | Yes | Shared secret token validated on every Pub/Sub push request. Must match the token configured in the Pub/Sub push subscription's `Authorization: Bearer` header. Generate: `python3 -c "import secrets; print(secrets.token_urlsafe(32))"` |

---

## Content AI (GLM via Vertex AI)

SEGS uses Zhipu/GLM via Vertex AI Model Garden for content analysis. The provider uses an OpenAI-compatible API; the `openai` Python package is used.

| Variable | Default | Required | Description |
|----------|---------|----------|-------------|
| `SEG_CONTENT_PROVIDER` | `glm` | Yes | AI provider: `glm` (Zhipu/GLM), `claude` (Claude via Bedrock), `disabled` |
| `SEG_GLM_MODEL_ID` | — | Yes | Primary GLM model ID. Example: `glm-4-flash` |
| `SEG_GLM_API_KEY` | — | Yes | GLM API key. Leave empty if using service account authentication via `SEG_GLM_CREDENTIALS_PATH`. |
| `SEG_GLM_PROJECT_ID` | — | Yes | GCP project ID hosting the GLM deployment in Vertex AI Model Garden. |
| `SEG_GLM_ENDPOINT` | auto | No | Custom endpoint URL. Defaults to the standard Vertex AI Model Garden endpoint for the project. |
| `SEG_GLM_FALLBACK1_MODEL_ID` | — | No | First fallback model ID if the primary model is unavailable. |
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
| `SEG_S3_BUCKET` | `""` | S3 bucket name. Leave empty to disable shipping. When set, the shipper thread starts automatically at container boot. |
| `SEG_S3_PREFIX` | `segs/logs` | S3 key prefix. Keys follow the pattern `{prefix}/{source}/{YYYY}/{MM}/{DD}/{HHMMSS}-{uuid}.jsonl.gz`. |
| `SEG_S3_REGION` | `ap-southeast-1` | AWS region for the S3 client. Defaults to `AWS_REGION` env var, then `ap-southeast-1`. |
| `SEG_S3_SHIP_INTERVAL` | `60` | Flush interval in seconds. The shipper wakes up every N seconds, reads new log lines since the last checkpoint, and uploads a gzip-compressed JSONL batch to S3. |

**Log sources shipped:**

| Source name | Local file | Description |
|-------------|-----------|-------------|
| `activity_audit` | `data/activity_audit.jsonl` | Admin actions: login, release, block, user changes, settings saves |
| `shadow_enforcement` | `gateway/spool/shadow_logs/shadow_enforcement.jsonl` | Shadow-mode enforcement decisions (emails that would have been quarantined/rejected) |

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

Configured in `rules/org.yaml` (committed) plus environment overrides:

| Variable | Default | Description |
|----------|---------|-------------|
| `SEG_ORG_NAME` | From `rules/org.yaml` | Organization display name shown in alerts and dashboard header |
| `SEG_ORG_DOMAIN` | From `rules/org.yaml` | Primary email domain (used in sender analysis) |

`rules/org.yaml` current values:
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

These files live in `rules/` and are committed to the repository. They define the default detection policy and can be tuned without code changes. Changes take effect on the next pipeline run (no restart needed for most files; `enforcement_mode.yaml` is hot-reloaded).

| File | Purpose |
|------|---------|
| `rules/org.yaml` | Organization metadata (name, domain, VIP titles) |
| `rules/weights.yaml` | Per-finding-type scoring weights |
| `rules/disposition.yaml` | Verdict → disposition mapping and hard overrides |
| `rules/enforcement_mode.yaml` | Override enforcement mode (read at runtime, hot-reloaded) |
| `rules/trusted_domains.txt` | Known-good partner domains (reduces edit-distance false positives) |
| `rules/trusted_senders.txt` | Specific sender addresses that always score CLEAN |
| `rules/blocked_senders.txt` | Sender addresses that always score MALICIOUS |
| `rules/risky_tlds.txt` | TLD penalty list (extra score for domains with these extensions) |
| `rules/banned_extensions.txt` | Attachment extensions that are always flagged (e.g. `.exe`, `.iso`, `.scr`) |

### Tuning `rules/weights.yaml`

Each finding type has a weight in [0, 10]. The total score is the sum of all triggered findings' weights. Thresholds (by default: 3 = LOW, 5 = SUSPICIOUS, 8 = MALICIOUS) are in `rules/disposition.yaml`.

Finding type naming conventions:
- `header_*` — Stage 1 (headers)
- `sender_*` — Stage 2 (sender identity)
- `url_*` — Stage 3 (URLs)
- `attach_*` — Stage 4 (attachments)
- `content_*` — Stage 5 (content AI)
- `brand_*` — Stage 6 (brand abuse)
- `intel_*` — Stage 7 (threat intel)
- `ioc_*` — Stage 8 (IOC correlation)

### Hard overrides in `rules/disposition.yaml`

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
| `EFS_FILESYSTEM_ID` | `deploy/update-service.sh` | EFS file system ID (format: `fs-xxxxxxxx`) |
| `ECS_CLUSTER` | `deploy/update-service.sh` | ECS cluster name (default: `segs`) |

---

## Defense in Depth — Attachment Inspection Layers

SEGS inspects attachments through **four independent layers**. Each layer compensates for the blind spots of the others. They always run in this order:

| Layer | What it catches | Always runs? | Requires |
|-------|----------------|--------------|---------|
| **① Static forensics** (`app/attachment_forensics.py`) | File-type spoofing (magic-byte vs extension), zip-bombs, Office macros (OLE + OOXML), PDF active content tokens, HTML credential forms, executable content, byte entropy | Yes — unconditional, offline, stdlib-only | Nothing |
| **② ClamAV AV scan** (`app/pipeline/sandbox.py`) | Known malware signatures, ransomware families, known phishing kits, known malicious macros — the entire ClamAV signature database | No — opt-in; activates when `SEG_SANDBOX_PROVIDER=clamav` | `pyclamd` + running `clamd` daemon |
| **③ VT hash reputation** (`app/pipeline/intel.py`, Stage 7) | Files already seen and confirmed malicious by the global VT community | No — requires `SEG_INTEL_CLIENT=vt_abuseipdb` + `SEG_VT_API_KEY` | VirusTotal API key |
| **④ LLM content reasoning** (`app/pipeline/content_ai.py`, Stage 5) | Novel social engineering in VBA macro code strings, HTML phishing page lure text, context mismatches between email body and attachment content — what signatures cannot reason about | No — requires a real LLM provider (GLM, Bedrock, Gemini, Ollama) | LLM provider + API key |

**ClamAV is purely additive.** Disabling or misconfiguring it does not affect the other layers. If `clamd` is unreachable, the pipeline logs `sandbox_clam_unavailable` and continues normally — the existing static forensics verdict stands.

### ClamAV configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SEG_SANDBOX_PROVIDER` | `null` | Set to `clamav` to activate ClamAV scanning. Any other value keeps the no-op stub. |
| `SEG_CLAMD_HOST` | `localhost` | clamd daemon hostname (used when `SEG_CLAMD_SOCKET` is not set). |
| `SEG_CLAMD_PORT` | `3310` | clamd TCP port. |
| `SEG_CLAMD_SOCKET` | — | Unix socket path (e.g. `/var/run/clamav/clamd.ctl`). When set, takes priority over host:port. Preferred for same-host/sidecar deployments. |

**Activation checklist:**
1. Install `pyclamd`: add `pyclamd` to `requirements.txt` (uncomment the stub) and rebuild the container.
2. Ensure `clamd` is running and reachable from the SEGS container (sidecar or shared service).
3. Set `SEG_SANDBOX_PROVIDER=clamav` in AWS Secrets Manager (`segs/prod`).
4. Verify: upload an EICAR test EML via the Analyzer — the report should show `🔴 MALICIOUS — Eicar-Signature` in the Attachment Detail table and a `clam_malicious` hard override.

The `virtual_analyzer` policy category in `rules/policy.yaml` gates whether a ClamAV hit fires the hard override. It defaults to `enabled: true`. To suppress ClamAV scoring without removing the env var, set `virtual_analyzer: enabled: false` in `rules/policy.yaml` — the scan still runs and is logged, but contributes nothing to the verdict.

---

## JumpCloud SSO (planned future — disabled by default)

The platform is SSO-ready. The `SSOMiddleware` in `server/security.py` reads `SEG_SSO_PROVIDER` at startup. When empty (the default), the middleware is a no-op and the platform uses its own session-cookie login. Set to `alb_oidc` to activate the JumpCloud SSO gate with no code changes.

| Variable | Description |
|----------|-------------|
| `SEG_SSO_PROVIDER` | Set to `alb_oidc` to require an AWS ALB OIDC token (JumpCloud). Empty = disabled (default). |
| `SEG_OIDC_CLIENT_ID` | JumpCloud OIDC app Client ID — the ALB listener uses this directly; stored here for documentation. |
| `SEG_OIDC_CLIENT_SECRET` | JumpCloud OIDC app Client Secret — same note. |
| `SEG_OIDC_ISSUER` | JumpCloud OIDC discovery base URL (`https://oauth.id.jumpcloud.com`). |

All four are stored as comments in `.env.example` and become active entries in `segs/prod` Secrets Manager when SSO is enabled. See `docs/JUMPCLOUD_SSO.md` for the full activation walkthrough.

---

## Environment variable load order

For local development (`.env` file):
```
.env → app/config.py defaults
```

For production (ECS Fargate):
```
AWS Secrets Manager segs/prod → ECS task environment → entrypoint.sh (writes credentials.json) → app/config.py defaults
```

The `entrypoint.sh` script runs at container start and:
1. Reads `SEGS_GMAIL_CREDENTIALS_JSON` from the environment
2. Writes it to `$SEG_GMAIL_CREDENTIALS` (default: `/opt/segs/credentials.json`)
3. Sets `chmod 600` on the file
4. Starts uvicorn

This means `credentials.json` is never in the container image and never persists between deployments.
