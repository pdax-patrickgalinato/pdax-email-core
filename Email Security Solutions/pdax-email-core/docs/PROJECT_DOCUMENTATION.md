# PDAX Email Security — Project Documentation

**Project:** `pdax-email-core` · Secure Email Gateway Suite (SEGS)
**Reference:** PDAX-PROP-SEC-001
**Last updated:** 2026-08-24

This is the complete, current reference for the project. It covers the detection
pipeline, the web dashboard/API server, the security posture, configuration, and
how to run and extend everything. For narrower docs see
[`README.md`](../README.md) (pipeline + provider wiring),
[`QUICKSTART.md`](../QUICKSTART.md), [`HANDOFF.md`](../HANDOFF.md) (decision log),
and [`MACOS-SETUP.md`](../MACOS-SETUP.md).

---

## 1. What this is

A transport-agnostic email threat-analysis engine plus a hardened web console for
security analysts. The same detection core (`run_pipeline()`) powers three entry
points with identical logic:

- **CLI** (`analyze.py`) — analyze a `.eml` file, offline.
- **Web app** (`server/`) — a FastAPI backend + single-page dashboard for live
  triage, quarantine review, deep analysis, and policy control.
- **Gateway** (planned/wired) — an inline SMTP hold consumer and a post-delivery
  Gmail-API receiver, both calling the same pipeline.

It runs **fully offline by default** — no cloud, no API keys required — so
detection logic can be developed and tuned on sample mail, then have production
enrichment providers (LLMs, threat intel, RDAP) switched on per environment
variable without touching pipeline code.

---

## 2. Architecture at a glance

```
                        ┌─────────────────────────────────────────┐
   .eml / raw bytes ──► │            run_pipeline()                │
                        │         (app/pipeline/runner.py)         │
                        │                                          │
                        │  headers → sender → urls → deception →   │
                        │  attachments → intel → content_ai        │
                        │                    │                     │
                        │            verdict.score_and_verdict     │
                        │            detection_rules.match_rules   │
                        │            disposition.apply             │
                        └───────────────────┬──────────────────────┘
                                            │  PipelineResult
        ┌───────────────────────────────────┼───────────────────────────────┐
        ▼                                   ▼                               ▼
   analyze.py (CLI)              server/ (FastAPI + dashboard)       gateway hold consumer
   text / JSON / Slack           RBAC · feed · quarantine · policy    (SMTP inline, planned)
```

Two layers:

- **`app/`** — the detection core. Pure analysis; no web framework, no I/O side
  effects beyond optional enrichment calls and the correlation store.
- **`server/`** — the web application. Auth, RBAC, the live feed, quarantine
  actions, deep-analysis uploads, policy toggles, and all the security middleware.
  Depends on `app/`; `app/` never depends on `server/`.

---

## 3. Detection pipeline

`run_pipeline(raw, source=...)` runs seven analysis stages, each returning a
`StageResult` (sub-score + red-flag list + facts). A broken stage is isolated —
it degrades to an `ERROR` result and never sinks the pipeline.

| # | Stage | Module | What it detects |
|---|-------|--------|-----------------|
| 1 | **Headers** | `pipeline/headers.py` | Authentication-Results (SPF/DKIM/DMARC), Return-Path / Reply-To / Message-ID anomalies |
| 2 | **Sender** | `pipeline/sender.py` | Lookalike domains (homoglyph + edit-distance), VIP spoofing, freemail personas, RDAP domain age |
| 3 | **URLs** | `pipeline/urls.py` | Anchor/href mismatch, lookalike URLs, brand keywords, risky TLDs, IP-literal links, link shorteners |
| 4 | **Deception** | `pipeline/deception.py` | Trusted-channel abuse; brand-vs-sending-platform structural mismatch |
| 5 | **Attachments** | `pipeline/attachments.py` | Type policy, banned extensions, HTML credential forms, SHA-256, static forensic severity |
| 6 | **Intel** | `pipeline/intel.py` | Threat-intel reputation (VirusTotal / AbuseIPDB) + behavioral correlation |
| 7 | **Content AI** | `pipeline/content_ai.py` | LLM/heuristic phishing-language analysis (advisory sub-score only) |

Then, post-stages:

- **`verdict.py`** — IOC extraction + scoring engine (below).
- **`detection_rules.py`** — named rules (`rules/detection_rules.yaml`) evaluated
  against the full flag set, so a rule can combine signals from any stage.
- **`disposition.py`** — maps the final verdict to a gateway action.

> **Note on stage order:** intel runs *before* content_ai so the LLM-triage
> decision (below) sees the full non-content picture — including any threat-intel
> hard override — before deciding whether an AI call is worth its cost.

### 3.1 Scoring model

- **Hard overrides** bypass weighting for high-confidence cases → straight to
  **MALICIOUS**: threat-intel hit, sender/URL lookalike domain, banned
  attachment, and BEC VIP-impersonation (VIP-name spoof + gift-card/wire language
  co-occurring).
- **Weighted composite** uses a *max-plus blend* (dominant signal + damped sum of
  the rest), not a plain average — so several independent moderate signals
  reinforce rather than dilute toward zero. Weights and thresholds live in
  [`rules/weights.yaml`](../rules/weights.yaml).
- **The AI stage only ever contributes a weighted sub-score.** It cannot set the
  verdict. This is the prompt-injection containment guarantee: a malicious email
  body cannot talk the model into an action, because the deterministic engine owns
  every decision.

**Default thresholds** (`rules/weights.yaml`):

| Verdict | Composite score |
|---------|-----------------|
| CLEAN | `< 20` |
| LOW | `20–44` |
| SUSPICIOUS | `45–64` |
| MALICIOUS | `≥ 65` |

**Stage weights:** headers 20 · sender 15 · urls 20 · deception 20 ·
attachments 15 · content_ai 15 · intel 20 (a hit is a hard override; the weight
applies only to degraded/non-hit cases).

### 3.2 Verdict → disposition → enforcement

Disposition ([`rules/disposition.yaml`](../rules/disposition.yaml)) maps a verdict
to an action; **AI never writes disposition**.

| Verdict | Action |
|---------|--------|
| CLEAN | DELIVER |
| LOW | LOG (deliver + audit) |
| SUSPICIOUS | QUARANTINE |
| MALICIOUS | QUARANTINE (may REJECT only in reject mode when explicitly allowed) |

**Enforcement modes** (`SEG_ENFORCE`, default `shadow`):

- `shadow` — log the intended action, always release. **Safe default.**
- `quarantine` — actually quarantine QUARANTINE dispositions; never hard-reject.
- `reject` — as quarantine, but MALICIOUS may become a 550 REJECT *only* when
  `allow_reject_on_malicious: true`.

Per HANDOFF.md: prefer quarantine over reject until shadow false-positives ≈ 0 —
a 550 loses mail permanently; a quarantine is reversible. On heavy pipeline
error the default is **fail-open** (deliver), so a broken enrichment source never
becomes a mail outage.

### 3.3 Behavioral correlation

`pipeline/correlation.py` maintains a rolling 6-month behavioral baseline in
`data/behavior_history.sqlite3`, recording sender↔IP and shortener associations
for **all** mail (not just flagged mail). It flags campaign patterns:

- **Sender/IP drift** (suspicious) — one sender across many IPs, or one IP across
  ≥5 senders (shared attack platform).
- **IP-shortener abuse** (suspicious) — an IP that sends link-shortener URLs.
- **Cross-sender shortener sharing** (malicious) — different senders using the
  same shortener domain (coordinated campaign).

Off by default; enable with `SEG_CORRELATION_STORE=1` for gateway/production use.

---

## 4. Web application (`server/`)

A FastAPI backend serving a single-file dashboard (`dashboard/index.html`) with a
JSON API. It is a **local admin console**, hardened as if internet-exposed.

### 4.1 Modules

| Module | Responsibility |
|--------|----------------|
| `server/main.py` | App entry point, middleware wiring, startup hardening, static mount |
| `server/security.py` | Rate limiting, body-size cap, path-traversal validation, security headers |
| `server/auth_store.py` | Users + sessions (SQLite), PBKDF2 password hashing |
| `server/deps.py` | Session resolution, `require_role()` RBAC dependency factory |
| `server/activity_log.py` | Append-only audit log of console actions |
| `server/feed_builder.py` | Builds the live-feed data model from pipeline output |
| `server/routers/auth.py` | Setup wizard, login/logout, current-user, user management |
| `server/routers/feed.py` | Live feed + quarantine actions (release/keep/re-evaluate/download) |
| `server/routers/analyze.py` | Deep-analysis EML upload endpoint |
| `server/routers/policy.py` | Read/write protection-policy toggles |

### 4.2 RBAC

Three roles, gated via `Depends(require_role(...))`:

- **admin** — full control incl. user management and policy writes.
- **analyst** — triage, quarantine actions, deep analysis, read policy.
- **viewer** — read-only.

Sessions are opaque server-side tokens (SQLite), 12-hour TTL, capped at 10
concurrent per user, revocable by deleting the row. First run presents a
one-time setup wizard to create the initial admin.

### 4.3 API surface (summary)

| Method & path | Auth | Purpose |
|---------------|------|---------|
| `GET /api/health` | public | Liveness check |
| `GET /api/setup/status` | public (rate-limited) | Whether first-run setup is needed |
| `POST /api/setup` | public, first-run only | Create initial admin |
| `POST /api/auth/login` | public (rate-limited) | Log in, set session cookie |
| `POST /api/auth/logout` | session | Revoke sessions |
| `GET /api/auth/me` | session | Current user |
| `GET /api/org` | session | Org branding/identity |
| `GET/PUT /api/policy` | analyst / admin | Read / write policy toggles |
| `GET /api/feed` + quarantine actions | analyst | Live feed & disposition actions |
| `POST /api/analyze/eml` | analyst | Deep analysis of an uploaded EML |
| `GET/POST/DELETE /api/users…` | admin | User management |

Interactive API docs (`/docs`, `/redoc`, `/openapi.json`) are **disabled** in this
build to prevent route enumeration.

---

## 5. Security posture

The app has been through a VAPT-hardening pass aligned to the OWASP Top 10. See
the dedicated summary for finding-by-finding detail; the controls now in place:

**Authentication & sessions**
- Brute-force rate limiting: 10 attempts / 5 min per IP; 5 / 10 min per username
  with a 15-min lockout (`server/security.py`).
- Timing-oracle defense: a dummy PBKDF2 hash is computed for unknown/disabled
  users so response time can't enumerate valid usernames.
- PBKDF2-SHA256, 200k iterations, 128-bit per-user salt; `secrets.compare_digest`
  comparisons.
- Session TTL (12h), per-user cap (10) with oldest-eviction, expiry pruning.
- Cookies: `HttpOnly` + `SameSite=Strict` always; `Secure` when
  `SEG_COOKIE_SECURE=1` (HTTPS).

**Injection defenses**
- **Path traversal:** `validate_queue_id()` strict-slug check on every spool
  endpoint + `assert_within_root()` containment on downloads.
- **SSRF:** RDAP domain sanitization (DNS-name regex, IDN/punycode normalize,
  percent-encode) before any outbound request; `landing_fetch.py` blocks private
  and loopback ranges and the `169.254.169.254` metadata endpoint, with redirect
  and timeout limits.
- **XSS:** dashboard render paths escape untrusted values (`escapeHtml()`) and a
  Content-Security-Policy is enforced as a second layer.
- **Log injection:** audit-log fields strip CR/LF/NUL and truncate before write.

**Attack surface & transport**
- Full security-header suite on every response: CSP, HSTS (under HTTPS),
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`,
  `Permissions-Policy`, `Cache-Control: no-store`.
- API docs disabled; `/api/org` auth-gated; `Server`/`X-Powered-By` stripped;
  same-origin CORS; 16 MB request body cap; sanitized client error messages.

**Secrets & filesystem**
- `.env` (`600`), `gateway/spool/` (`700`/`600`), `rules/` (`640`).
- Startup routine recursively re-locks `data/` and `gateway/spool/` on **every
  boot**, so runtime-created files stay owner-only.
- `.env`, `data/`, and spool contents are gitignored and never committed.

**Verified safe (audited, no change needed):** policy-write path (allowlisted
category + `re.escape` + post-write re-validation), deception ReDoS surface
(`re.escape`), landing-fetch SSRF guards.

---

## 6. Configuration

### 6.1 Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `SEG_CONTENT_PROVIDER` | `heuristic` | AI provider: `heuristic` / `bedrock` / `gemini` / `glm` / `ollama` / `null` |
| `SEG_LLM_TRIAGE` | off | Only spend an LLM call on ambiguous cases (production volume control) |
| `SEG_LLM_TRIAGE_MARGIN` | `15` | Score distance from a threshold that counts as "ambiguous" |
| `SEG_INTEL_CLIENT` | local | `vt_abuseipdb` to enable VirusTotal/AbuseIPDB |
| `SEG_VT_API_KEY` / `SEG_ABUSEIPDB_API_KEY` | — | Intel provider keys (either/both) |
| `SEG_CORRELATION_STORE` | off | Enable behavioral correlation write-back |
| `SEG_RDAP_LOOKUP` | off | Enable RDAP domain-age lookups (Web Reputation) |
| `SEG_ENFORCE` | `shadow` | Enforcement mode: `shadow` / `quarantine` / `reject` |
| `SEG_COOKIE_SECURE` | off | Set `Secure` cookie flag + HSTS (enable behind TLS) |
| `SEG_MAX_BODY_BYTES` | `16777216` | Request body size cap |

**Provider-specific** (only when that provider is selected):

- **Bedrock:** `AWS_REGION` (default `ap-southeast-1`), `SEG_BEDROCK_MODEL_ID`.
- **Gemini:** `SEG_GEMINI_API_KEY`, `SEG_GEMINI_MODEL_ID` (default
  `gemini-flash-latest`). ⚠️ Google AI Studio — no region pinning; needs DPO
  sign-off under RA 10173 before real mail.
- **GLM:** `SEG_GLM_CREDENTIALS_PATH` (GCP service-account JSON) or
  `SEG_GLM_API_KEY`, `SEG_GLM_MODEL_ID`. ⚠️ Third-party model provenance
  (Zhipu/Z.ai) + `locations/global` endpoint — get sign-off.
- **Ollama:** `SEG_OLLAMA_MODEL_ID` (a locally `ollama pull`-ed model). No
  data-residency question and no per-call cost — the recommended production
  default once hardware is provisioned.

See [`README.md`](../README.md) for the full provider-wiring detail and the
shared prompt/schema contract.

### 6.2 Rules files (`rules/`)

| File | Purpose |
|------|---------|
| `weights.yaml` | Stage weights + verdict thresholds |
| `disposition.yaml` | Verdict → gateway action mapping |
| `detection_rules.yaml` | Named multi-signal detection rules |
| `policy.yaml` | Protection-policy toggles (mirrors TMES categories) |
| `banned_extensions.txt` | Blocked attachment extensions |
| `protected_domains.txt` | Domains protected from lookalike/spoofing |
| `vip_names.txt` | VIP names for impersonation detection |
| `freemail_domains.txt` | Freemail providers (persona detection) |
| `impersonation_brands.txt` | Brands checked for impersonation |
| `trusted_platforms.yaml` | Legitimate sending platforms (deception stage) |
| `org.yaml` | Organization branding/identity |

---

## 7. Running it

### 7.1 Setup

```bash
cd "Email Security Solutions/pdax-email-core"
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### 7.2 CLI (offline, no server)

```bash
python3 analyze.py samples/phish_lookalike.eml       # human-readable report
python3 analyze.py samples/bec_giftcard.eml --json   # JSONL audit record
python3 analyze.py samples/clean_normal.eml --slack  # Slack Block Kit payload
python3 tests/run_eval.py samples/                   # precision/recall on a corpus
```

### 7.3 Web app

```bash
./start_server.sh
# or:
uvicorn server.main:app --host 127.0.0.1 --port 8765 --no-server-header
```

Then open **http://127.0.0.1:8765/**. On first run you'll get the setup wizard to
create the initial admin; after that, sign in (role-gated: Admin / Analyst /
Viewer).

For production behind TLS: set `SEG_COOKIE_SECURE=1` to activate the `Secure`
cookie flag and HSTS.

---

## 8. Testing

```bash
source .venv/bin/activate
python3 -m pytest tests/ -q          # full suite
python3 -m pytest tests/test_rdap.py tests/test_server_auth.py -v   # focused
```

Current status: **267 tests passing**, 0 known dependency CVEs (`pip-audit`).
Coverage spans the pipeline stages, each AI provider, the intel/correlation
layer, the server API (auth, feed, policy, analyze), and the security regression
tests (RDAP sanitizer, auth gating, rate limiting).

Python 3.9 syntax compatibility is maintained across all modules (checked in CI-style
via `ast.parse`).

---

## 9. Project layout

```
analyze.py                  CLI entry point
start_server.sh             Web app launcher
requirements.txt            Core deps (pydantic, PyYAML, fastapi, uvicorn)

app/                        DETECTION CORE
  models.py                 pydantic schemas (Verdict, StageResult, PipelineResult, IOCSet)
  parsed_email.py           stdlib email wrapper (urls, anchors, attachments, IPs)
  domainutils.py            registrable domain, homoglyph fold, bounded levenshtein
  disposition.py            verdict → gateway action + enforcement modes
  report.py                 text / Slack / JSONL renderers
  rdap_client.py            RDAP domain-age lookup (sanitized, SSRF-safe)
  landing_fetch.py          isolated URL fetch with SSRF guards
  attachment_forensics.py   static attachment severity
  url_forensics.py          URL forensic analysis
  org_config.py / lists.py  org identity, list loading
  pipeline/
    headers.py sender.py urls.py deception.py attachments.py
    intel.py content_ai.py       enrichment stages (pluggable providers)
    verdict.py                   IOC extraction + scoring engine
    correlation.py               behavioral correlation store
    detection_rules.py           named multi-signal rules
    sandbox.py                   sandbox stage
    policy.py                    policy category gating
    runner.py                    orchestrator (per-stage error isolation)

server/                     WEB APPLICATION
  main.py security.py auth_store.py deps.py activity_log.py feed_builder.py
  routers/ auth.py feed.py analyze.py policy.py

dashboard/                  Single-file SPA (index.html), login.html, assets
rules/                      Tunable config (weights, policy, detection rules, lists)
samples/                    Test .eml corpus + fixtures
data/                       SQLite stores (gitignored: users, sessions, correlation, cache)
gateway/spool/              Quarantine / released / rejected / shadow logs (gitignored)
docs/                       Reports + this documentation
tests/                      pytest suite + eval harness
```

---

## 10. Extending the system

Two Protocol interfaces make the enrichment stages swappable without touching
pipeline code:

- **Content provider (Stage 7):** implement
  `analyze(subject, body, context) -> (score, findings, facts)`. Output only ever
  becomes a sub-score — `verdict.py` still owns the decision.
- **Intel client (Stage 6):** implement
  `check(domains, ips, urls, hashes) -> (hits, degraded)`.

Both degrade honestly: a provider outage yields a zero/degraded sub-score, never
a raised exception, so no single enrichment source can sink the pipeline.

---

## 11. Production roadmap

1. Grow `samples/` into the real golden set (defanged TMES quarantine + crafted
   PDAX-targeted lures + legitimate traffic) and tune `weights.yaml` against
   `run_eval.py` until Annex B targets are met.
2. Provision hardware for **Ollama** (self-hosted, no data-residency question, no
   per-call cost) as the recommended production content provider.
3. Wire the real `IntelClient` (VirusTotal/AbuseIPDB via Bantay SOC) and enable
   `SEG_CORRELATION_STORE` + `SEG_RDAP_LOOKUP` in the gateway environment.
4. Wrap `run_pipeline` in the Gmail-API POC receiver (Annex B) and the SMTP hold
   consumer (Annex C).
5. Complete remaining hardening: nonce-based CSP (removes the last
   `'unsafe-inline'`), TLS termination with `SEG_COOKIE_SECURE=1`, and alerting on
   lockout/401 spikes from the activity audit log.
6. Calibrate `SEG_ENFORCE` from `shadow` → `quarantine` once shadow-mode
   false-positives are essentially zero on real traffic.
