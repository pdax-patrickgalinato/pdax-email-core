# Instructions for AI agents — SEGS (`pdax-email-core`)

Durable orientation for any agent working in this repository. Read this before
changing pipeline, verdict, provider, or policy code.

| Document | Role |
|----------|------|
| **This file** | Current agent contract: invariants, layout, how to verify a change |
| `docs/archive/claude.md` | Earlier agent notes. Some items have drifted. Prefer this file + the code |
| `docs/archive/handoff.md` | Project history, detection lessons, backlog narrative |
| `README.md` | Human onboarding (how to run locally and deploy) |
| `docs/architecture.md` | High-level Path A/B design. **Do not trust stage filenames or score scales there** — they do not match the code |
| `docs/configuration.md` | Env-var reference (also check `.env.example` and the code) |

Git root **is** the application root. Work from this directory.

---

## What this is

SEGS (Secure Email Gateway Suite) is the analysis core behind **PDAX-PROP-SEC-001**:
PDAX’s in-house replacement for Trend Micro Email Security (TMES). PDAX is a
BSP-supervised VASP in the Philippines; email content is in-scope for **RA 10173**
(Data Privacy Act). Do not silently route real mail to a third-party API without
flagging data-residency implications.

The pipeline is **transport-agnostic**. `run_pipeline(raw_bytes, source=...)` in
`workers/pipeline/runner.py` is the single entry point for CLI and eval. Live
Gmail mail is fetched by workers, split across parallel static jobs, then
assessed by the AI worker:

| Caller | `source=` | Role |
|--------|-----------|------|
| `cli.analyze` (`segs-analyze`) | `"file"` | Offline CLI — how you develop and tune |
| `workers.gmail` / `workers.receiver` | `"gmail_api"` | Gmail API poll (DWD, no push URL) |
| `backend.api` dashboard APIs | `"file"` / feed | Analyze tab (parked), feed reads SQLite |

Offline by default: no AWS, Gmail, or API keys required. Enrichment (LLM,
VirusTotal, AbuseIPDB, RDAP, landing fetch, ClamAV) is opt-in via `SEG_*` env
vars (`backend/config.py`) or constructor args, never required for the core to run.

---

## Architecture invariant — read before touching `verdict.py` or any provider

**AI and enrichment stages never set the verdict.** They return a weighted
sub-score and red-flag tags. `workers/pipeline/verdict.py` is the sole owner of every
`CLEAN` / `LOW` / `SUSPICIOUS` / `MALICIOUS` decision.

1. **Hard overrides** for high-confidence cases (bypass weighting).
2. Otherwise a **max-plus weighted composite**: dominant stage signal + damped
   sum of the rest. Do **not** average. Averaging buried a real BEC case.

A content provider’s return type is always `(score, findings, facts)`. Never
write `result.verdict` (or `result.disposition`) from model/API output. This is
the prompt-injection containment guarantee: a malicious body cannot talk an LLM
into an action.

The email body is attacker-controlled. Any LLM provider must treat injection
attempts as adversarial input to **detect**, not instructions to follow. Pattern:
shared `_SYSTEM_PROMPT` in `workers/pipeline/content_ai.py` — flag
`prompt_injection_attempt`, do not comply.

Disposition (`DELIVER` / `LOG` / `QUARANTINE` / `REJECT`) is applied **after**
the verdict in `backend/disposition.py` from `backend/policy/detection/disposition.yaml`. AI never
writes disposition.

---

## Pipeline as the code actually runs

`docs/architecture.md` lists a marketing 10-stage model with filenames like
`stage_headers.py`. Those files do not exist. Current `run_pipeline()` order:

```
headers → sender → urls → deception → attachments → intel → content_ai
       → extract_iocs → score_and_verdict → correlation write-back
       → detection_rules.match_rules → apply_disposition → allowlist/blocklist
```

Intel runs **before** content AI so LLM-triage can skip the paid call when a
threat-intel hard override already fired.

| Stage | Module | Notes |
|-------|--------|--------|
| headers | `workers/pipeline/headers.py` | SPF/DKIM/DMARC, Return-Path, Reply-To, Message-ID |
| sender | `workers/pipeline/sender.py` | Lookalike domains, VIP spoof, brand impersonation |
| urls | `workers/pipeline/urls.py` | Unwrap redirect params; score the *target*, not the tracker host |
| deception | `workers/pipeline/deception.py` | Trusted-channel + foreign brand lure (`backend/policy/identity/trusted_platforms.yaml`) |
| attachments | `workers/pipeline/attachments.py` | Banned types, forensics, optional ClamAV |
| intel | `workers/pipeline/intel.py` | Local IOC set or VT + AbuseIPDB; correlation is weighted-only |
| content_ai | `workers/pipeline/content_ai.py` | Heuristic default; LLM providers opt-in |
| scoring | `workers/pipeline/verdict.py` | Hard overrides + max-plus blend |

Every stage `run()` returns a `StageResult` (`backend/models.py`). The runner wraps
each call in `safe()` so one broken stage cannot sink the pipeline. New stages
must return a degraded/error `StageResult`, never raise out of `run()`.

---

## Scoring and hard overrides

Tune numbers in `backend/policy/detection/weights.yaml`, not in Python. Current thresholds:

- `low`: 20
- `suspicious`: 45
- `malicious`: 65

Stage `sub_score` is 0–100. Composite is a weighted max-plus blend, not a 0–8
scale.

Hard overrides in `verdict.py` (MALICIOUS, skip weighting):

| Override | Trigger |
|----------|---------|
| `threat_intel_hit` | `intel_*` flags (external/local IOC). Correlation-only hits are **not** this |
| `url_lookalike_domain` | `url_lookalike*` (policy: `web_reputation`) |
| `deception_structure_service_abuse` / `service_abuse_*` | Trusted platform + foreign brand lure (always on) |
| `banned_attachment_type` | `banned_attachment*` (policy: `file_blocking`) |
| `spoofed_or_double_extension_attachment` | Magic-byte mismatch / `invoice.pdf.exe` |
| `clam_malicious` | `sandbox_clam_found` (policy: `virtual_analyzer`) |
| `sender_lookalike_domain` | `lookalike_of*` (always on) |
| `bec_vip_impersonation` | `vip_name_spoof*` **and** `bec_pattern` (always on) |

After scoring, `runner._apply_list_overrides()` may force quarantine (blocklist)
or deliver (allowlist). The original score stays on the result for audit.

**AI verdict floor** (LLM providers only, not Heuristic/Null): if the model’s
threat classification confidence ≥ `ai_influence.verdict_floor_confidence`
(default 0.8, env `SEG_AI_VERDICT_FLOOR_CONF`), floor **up** to `SUSPICIOUS`.
Upward-only. Never lowers a verdict. Never reaches `MALICIOUS` on the AI’s
word alone.

Policy categories in `backend/policy/detection/policy.yaml` suppress flags from scoring/overrides;
stages still run and flags still appear in the report as policy-suppressed.

---

## Providers are pluggable (`typing.Protocol`)

Select via kwargs on `run_pipeline()` or `get_default_provider()` /
`get_default_intel_client()`. Do not hardcode a provider at new call sites.

**Content** (`SEG_CONTENT_PROVIDER`, default `heuristic`):
`NullProvider` | `HeuristicProvider` | `BedrockProvider` | `GeminiProvider` |
`GLMProvider` | `OllamaProvider`.

LLM providers share `_SYSTEM_PROMPT` and `_ContentAnalysis`. Tune analysis in
one place. GLM is the production-oriented Vertex Model Garden path
(`SEG_GLM_CREDENTIALS_PATH` or `SEG_GLM_API_KEY`). Gemini AI Studio has **no
region pinning** — flag RA 10173 / DPO before real mail. GLM’s documented
endpoint is `locations/global` and the model is third-party (Zhipu) — also
flagged, not assumed cleared.

**Intel** (`SEG_INTEL_CLIENT`, default `local`):
`LocalIOCClient` (offline) | `VTAbuseIPDBIntelClient` (`vt_abuseipdb`).
Implemented with stdlib `urllib` + SQLite cache. An intel hit is a hard
override. Correlation (`SEG_CORRELATION_STORE=1`) is weighted-only.

**LLM triage** (`SEG_LLM_TRIAGE=1`, off by default): heuristic pass first;
real LLM only if the score is within `SEG_LLM_TRIAGE_MARGIN` (default 15) of
the LOW/MALICIOUS thresholds and no hard override fired. Leave off when
debugging with the analyze CLI so an explicit provider is never silently skipped.

---

## Repository layout

```
backend/               FastAPI View + stores (API reads SQLite)
  config.py             pydantic-settings for SEG_* / SEGS_* (no .env auto-load)
  stores/               SQLite get/list (API) and put/upsert (workers)
  models.py             StageResult, PipelineResult, Verdict, Disposition
  parsed_email.py       MIME parse, header decode, originating IPs
  disposition.py        Verdict → spool action
  report.py             CLI / Slack / audit JSON (flag descriptions live here)
  api/                  FastAPI View (routers) + ViewModels (feed_builder)
  tests/
    pipeline/           Pipeline unit tests
    server/             Dashboard API tests
    tools/              Analyst-CLI tests
    eval/run_eval.py    Golden-set harness (FP=0)
    fixtures/eml/       Labeled .eml for pytest and eval
  policy/               weights, identity lists, runtime YAML
cli/                    Analyst CLIs — NOT part of scoring
workers/                python -m workers <name>  (one container per name)
  pipeline/             Stages + runner + verdict. AI never writes verdict.
  jobs.py               Durable SQLite queue so workers can be separate processes
web-console/            React + Vite SOC console (same-origin cookies)
email/spool/            Raw .eml blobs (gitignored). Override: SEG_QUARANTINE_ROOT
deploy/
  docker/               API + receiver Dockerfiles and entrypoint (used by infra/)
infra/                  Terraform: CloudFront/S3, ECR, Fargate, ALB+WAF, EFS
docs/archive/           Historical HANDOFF, CLAUDE, QUICKSTART, reports
```

`cli/eml_analysis_agent.py` and the dashboard Analyze tab produce investigator

## Job pipeline

Workers write SQLite; the API reads. Gmail poll enqueues one static job per
copy. The static worker runs every deterministic stage, then the AI assessment
engine runs (`workers/content_ai.py`). Thread AI runs when every copy in the
Gmail thread has a per-message assessment. Sender-profile and campaign
re-analysis follow AI (and again after thread AI). Analyze API is parked.
write-ups. They must not write `result.verdict`. Deterministic facts (hashes,
URLs, headers) are computed in Python; the model only adds judgment.

---

## Environment and language

- **Env prefix is `SEG_`**, not `PDAX_`. Older `docs/archive/handoff.md` entries are stale.
- Dev `.venv` should be Homebrew Python 3.12 (`/opt/homebrew/bin/python3.12`).
- **Source stays Python 3.9-parseable on purpose**:
  `from __future__ import annotations` is fine; PEP 585 generics (`list[str]`)
  are fine. Avoid `match`, `X | Y` unions outside annotations, `tomllib`.
  Do not drop this without asking the user. Verify with the `ast.parse`
  gate below.
- Offline core deps: `pydantic`, `PyYAML`. FastAPI stack is for the dashboard.
  Provider SDKs (`openai`, `boto3`, `google-genai`) are optional / lazy.

Never commit `credentials.json`, `.env`, `data/`, or `email/spool/` mail.

---

## Conventions

- Module docstrings explain *why* a stage exists. Function docstrings only for
  non-obvious behavior. No docstring bloat.
- New detection rules come from a real miss, get **generalized**, and are
  checked against legitimate samples before merge. A rule not tested on clean
  mail is a future false positive.
- `backend/policy/` YAML/txt is data. Tune thresholds
  and lists there.
- After adding a flag, add a human description in `backend/report.py`
  (`_FLAG_DESCRIPTIONS` / `_FLAG_PREFIX_DESCRIPTIONS`) and run
  `python -m cli.build_flag_descriptions` so the dashboard stays in sync.
- Server tests use FastAPI `TestClient`, monkey-patch module-level paths to
  temp dirs, and **must not** touch real `data/`, `email/spool/`, or
  `backend/policy/`.
- Sanitize attacker-controlled From/Subject before any output surface
  (`report.py`: control chars, Slack metacharacters).

### Detection lessons (do not re-learn)

- Averaging dilutes strong signals — keep combination hard overrides.
- Open-redirect abuse hides payload domains inside legitimate tracker URLs.
  Unwrap `td_redirect=` and similar; **do not** flag a redirect whose target
  is the sender’s own domain (legitimate trackers).
- Compromised legitimate senders pass SPF/DKIM/DMARC. Auth is not decisive.
- Phishing is often several moderate signals, not one smoking gun.
- Trusted-channel abuse (e.g. authentic Apple TestFlight + foreign brand lure)
  looks auth-clean on purpose. That is a deception-structure problem, not a
  spoof problem.

---

## Security and compliance constraints

- Do **not** upload PDAX documents or real attachments to public sandboxes
  (VirusTotal file upload). Hash lookup only.
- `SEG_LANDING_FETCH` follows attacker URLs from this host (SSRF-guarded, but
  still egress/fingerprint risk). Keep off unless isolated egress is explicit.
  Prefer VirusTotal URL lookup for live URL intel.
- Fail-open on pipeline error is the current policy
  (`backend/policy/detection/disposition.yaml` `on_pipeline_error: DELIVER`). A broken enrichment
  source must not become a mail outage. Do not silently switch to fail-closed.
- `allow_reject_on_malicious` stays `false` until shadow-mode FP is essentially
  zero. A 550 loses mail; quarantine is reversible.
- Default enforce mode is **shadow** (`SEG_ENFORCE`). Do not assume quarantine
  or reject is active.

---

## Definition of done

From this directory (`uv sync --extra dev`; `pip install -e ".[dev]"` also works):

```bash
uv sync --extra dev
uv run pytest
uv run python backend/tests/eval/run_eval.py backend/tests/fixtures/eml/   # gate is FP=0 on clean-labeled mail, not recall=1
uv run ruff check backend workers cli
uv run python -c "import ast,pathlib;[ast.parse(p.read_text(),feature_version=(3,9)) for p in pathlib.Path('.').rglob('*.py') if '.venv' not in str(p) and 'egg-info' not in str(p) and 'node_modules' not in str(p)]"
```

`backend/tests/eval/run_eval.py` scores labeled fixtures via `backend/tests/fixtures/eml/labels.yaml`.
`suspicious` and `malicious` labels both count as the malicious class.
**Pass/fail is FP=0** (no clean mail marked SUSPICIOUS/MALICIOUS). Recall on
this corpus is a known gap, not a hard-fail. Do not “fix” eval by relabeling
clean mail without a real content reason.

Synthetic fixtures live in `backend/tests/fixtures/eml/` and are covered by
`backend/tests/pipeline/test_core.py` as well as `run_eval.py`.

If you add a new test module, put it under `backend/tests/pipeline/`,
`backend/tests/server/`, or `backend/tests/tools/` so `pytest` collects it.
Do not add a homemade `__main__` runner.

---

## Local commands

```bash
# Offline analysis
uv run python -m cli.analyze backend/tests/fixtures/eml/phish-lookalike.eml
uv run python -m cli.analyze path/to/message.eml --json    # audit JSONL
uv run python -m cli.analyze path/to/message.eml --slack

# Dashboard (http://127.0.0.1:8765)
(cd web-console && npm install && npm run build)
bash start_server.sh
```

---

## What not to do

- Do not let any provider or LLM write `result.verdict` or `result.disposition`.
- Do not replace max-plus scoring with a plain average.
- Do not hardcode scores, banned extensions, VIP names, or protected domains
  in Python — use `backend/policy/`.
- Do not enable network enrichments as the new default.
- Do not scrape LinkedIn/Google or invent OSINT the pipeline did not fetch.
- Do not treat `docs/architecture.md` stage names/thresholds or
  `docs/archive/handoff.md` `PDAX_*` env vars as current.
- Do not skip the 3.9 parse gate or the FP=0 eval after detection changes.

---

## First thing in a new session

```bash
source .venv/bin/activate
python3 backend/tests/pipeline/test_core.py
python3 backend/tests/eval/run_eval.py backend/tests/fixtures/eml/
uv run python -m cli.analyze backend/tests/fixtures/eml/phish-lookalike.eml
```

Then read `docs/archive/handoff.md` only for history and open backlog items.
Confirm against the code whether a listed “stub” is still a stub.
