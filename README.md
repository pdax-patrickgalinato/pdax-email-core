# SEGS — Secure Email Gateway Suite

**PDAX-PROP-SEC-001** · Internal platform to detect, quarantine, and investigate email-based threats against PDAX's Google Workspace environment.

SEGS runs a 10-stage analysis pipeline on every inbound email — inspecting headers, sender identity, URLs, attachments, and content — and classifies each as CLEAN, LOW, SUSPICIOUS, or MALICIOUS. Quarantined emails appear in the SOC dashboard for analyst review, release, or escalation.

---

## Architecture overview

```
Internet → Google Workspace → Gmail inbox
                 │
       python -m workers gmail_poll
                 │
       python -m workers static   (headers, sender, URLs, intel, sandbox, …)
                 │
       python -m workers content_ai → SQLite
                 │
              SOC Dashboard (API reads SQLite)
```

| Mode | What it does | Deployment |
|------|-------------|------------|
| **Gmail poll** (active) | Post-delivery **read-only** Gmail API poll. Email stays in the inbox; workers write analysis to SQLite. No MX changes. | ECS Fargate, ap-southeast-1 |

See [docs/architecture.md](docs/architecture.md) for the full design.

---

## Documentation

| Guide | Audience | Contents |
|-------|----------|----------|
| [OpenAPI](docs/openapi.yaml) | Integrators / infra | HTTP API contract. API Gateway imports the Terraform copy in `infra/openapi.yaml` |
| [Deployment](docs/deployment.md) | Ops/DevOps | AWS ECS Fargate step-by-step deployment guide |
| [Gmail API Setup](docs/gmail-api-setup.md) | Ops/DevOps | GCP project, Pub/Sub, domain-wide delegation walkthrough |
| [Operations](docs/operations.md) | SOC analysts | Day-to-day: reviewing alerts, releasing quarantine, managing users |
| [Configuration](docs/configuration.md) | Ops/DevOps | All environment variables and configuration files |
| [Agent instructions](instructions.md) | AI agents | Invariants, layout, how to verify a change |
| [Archive](docs/archive/) | Maintainers | Historical HANDOFF, CLAUDE notes, QUICKSTART, reports |

---

## Repository layout

```
pdax-email-core/                # git root = application root
├── backend/                    FastAPI + stores (API reads SQLite)
│   ├── config.py               pydantic-settings for SEG_* / SEGS_*
│   ├── stores/                 SQLite get/list (API) and put/upsert (workers)
│   ├── api/                    FastAPI (port 8765) + SPA host
│   ├── policy/                 Detection weights, identity lists, runtime YAML
│   └── tests/
│       └── fixtures/eml/       Synthetic + regression .eml for pytest/eval
├── workers/                    One process per job: python -m workers <name>
│   ├── pipeline/               Stages, runner, verdict
│   ├── jobs.py                 Durable SQLite queue (cross-container)
│   └── gmail.py                Gmail API I/O
├── cli/                        Analyst CLIs (not the API)
├── web-console/                React + TypeScript Vite console (npm run build → dist/)
├── email/spool/                Raw .eml blobs (gitignored). Override: SEG_QUARANTINE_ROOT
├── deploy/
│   └── docker/                 API + receiver Dockerfiles, entrypoint
├── infra/                      Terraform (CloudFront, ECR, Fargate, ALB+WAF, EFS)
├── docs/                       Current operational docs
│   └── archive/                Historical notes and reports
├── start_server.sh             Local dashboard launcher
├── pyproject.toml              Package metadata + pytest/ruff
├── uv.lock                     Locked dependency graph
└── .env.example                Environment variable reference
```

---

## Local development (offline, no cloud)

The pipeline runs fully offline for development and tuning. On macOS, prefer
Homebrew Python 3.12 when creating the venv (`/opt/homebrew/bin/python3.12`);
system `python3` is often 3.9.

```bash
# 1. Install uv (https://docs.astral.sh/uv/) then sync the lockfile
uv sync --extra dev

# 2. Analyze a sample email
uv run python -m cli.analyze backend/tests/fixtures/eml/phish-lookalike.eml

# 3. Run unit tests, then the golden-set eval (gate is FP=0)
uv run pytest
uv run python backend/tests/eval/run_eval.py backend/tests/fixtures/eml/

# 4. Build the React console, then start the dashboard
(cd web-console && npm install && npm run build)
(cd web-console && npm test)            # Vitest unit tests
# (cd web-console && npm run test:e2e)  # Playwright (uses dist/ from the build)
bash start_server.sh
# → http://127.0.0.1:8765  (dashboard only — it does not drain mail queues)
# Gmail poll / static / AI are separate processes:
.venv/bin/python -m workers receiver          # all-in-one on :8766
# or one process each:  python -m workers gmail_poll | static | content_ai | …
# Optional live UI reload: npm run dev in web-console/ (proxies /api to :8765)
```

`pip install -e ".[dev]"` still works if you prefer a classic venv. Process
config is declared in `backend/config.py` (`SEG_*` / `SEGS_*` via pydantic-settings).

On first run the dashboard shows a setup wizard to create the admin account
(password: 8+ characters, upper, lower, number, special). Copy `.env.example`
to `.env` and add `credentials.json` at the repo root when you want GLM / Gmail
providers; then restart the server so it picks them up.

Optional MSOC-style batch reports (not part of scoring):

```bash
python3 -m cli.eml_analysis_agent path/to/mail.eml --output-dir data/eml-output
```

---

## Production deployment (AWS)

See [infra/README.md](infra/README.md) and [docs/deployment.md](docs/deployment.md).

```bash
cd infra
cp terraform.tfvars.example terraform.tfvars   # VPC + subnet IDs
terraform init && terraform apply
bash scripts/put-secrets.sh                    # from .env.prod
bash scripts/push-images.sh                    # then apply with printed digests
terraform apply -var sync_console=true         # after npm run build in web-console/
terraform output console_url
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

Controlled by `SEG_ENFORCE` (or `backend/policy/runtime/enforcement_mode.yaml` for live changes without redeployment):

| Mode | Behavior |
|------|----------|
| `shadow` | Log intended action only — all mail delivered normally. Use for tuning. |
| `quarantine` | SUSPICIOUS/MALICIOUS mail written to spool, removed from inbox. |
| `reject` | As quarantine, but MALICIOUS may also issue a 550 SMTP reject (Path B only). |

---

## Security posture

- **Dashboard**: CloudFront URL (login + rate limit). Session cookies: `Secure`, `HttpOnly`, `SameSite=Strict`. `/api` is same-origin via CloudFront.
- **Gmail receiver**: outbound poll of listed mailboxes via domain-wide delegation (`gmail.readonly`). Reads labels; does not change them. No public push endpoint.
- **Secrets**: all credentials in AWS Secrets Manager, injected at container start. No secrets in the Docker image or task definition plaintext.
- **Spool/data**: stored on EFS with transit encryption. `chmod 700` applied at startup.
- **CSP**: `script-src 'self' 'unsafe-inline'` (inline JS in dashboard). No external CDN dependencies.
- **Audit log**: all admin actions written to `data/activity_audit.jsonl` → CloudWatch → Wazuh.

---

## Compliance context

PDAX is a BSP-supervised VASP (Virtual Asset Service Provider) under RA 10173 (Data Privacy Act of the Philippines). SEGS processes email metadata and content within the organization's own AWS infrastructure (ap-southeast-1). The GLM content AI provider uses Vertex AI Model Garden — review data residency implications with DPO before processing live PII-containing emails.
