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
| `SEG_VT_API_KEY` | — | If intel enabled | VirusTotal API key. Free tier: 4 requests/minute. Hashes and URLs are looked up; results cached in `data/ioc_cache.db`. |
| `SEG_ABUSEIPDB_API_KEY` | — | If intel enabled | AbuseIPDB API key. Used to check sender IP reputation. |

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
