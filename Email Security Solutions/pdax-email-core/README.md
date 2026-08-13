# PDAX Email Security — Detection Core

The runnable heart of PDAX-PROP-SEC-001. This is the transport-agnostic
analysis pipeline that **both** the post-delivery POC (Annex B) and the inline
gateway (Annex C) call via `run_pipeline()`. It runs **fully offline** — no
AWS, no Gmail, no API keys — so you can develop and tune detection logic on
`.eml` files today, then wire the enrichment providers for production.

## Quick start

```bash
pip install -r requirements.txt
python3 analyze.py samples/phish_lookalike.eml     # human-readable report
python3 analyze.py samples/bec_giftcard.eml --json # JSONL audit record
python3 analyze.py samples/clean_normal.eml --slack# Slack Block Kit payload
python3 tests/run_eval.py samples/                 # precision/recall on a corpus
python3 tests/test_core.py                         # unit tests
```

Current sample results: clean → CLEAN, lookalike phish → MALICIOUS,
BEC gift-card → MALICIOUS (precision 1.0, recall 1.0 on the 3-sample set).

## What runs, and how it maps to the 10-stage design

| Stage | Module | Offline core | Production wiring |
|---|---|---|---|
| 1 Headers | `pipeline/headers.py` | Parses Authentication-Results + Return-Path/Reply-To/Message-ID anomalies | Rspamd re-verifies DKIM/DMARC cryptographically |
| 2 Sender | `pipeline/sender.py` | Lookalike (homoglyph+edit-distance), VIP spoof, freemail persona | + RDAP domain age, first-contact history |
| 3 URLs | `pipeline/urls.py` | Anchor/href mismatch, lookalike URLs, brand-keyword, risky TLD, IP-literal | + live redirect follow & cert inspection (isolated egress) |
| 4 Attachments | `pipeline/attachments.py` | Type policy, banned ext, HTML credential-form, SHA256 | + oletools/pdfid, live VT hash lookup |
| 5 Content AI | `pipeline/content_ai.py` | `HeuristicProvider` (keyword/urgency) | `BedrockProvider` (Claude/Bedrock), `GeminiProvider` (Gemini/Google AI Studio), or `GLMProvider` (Zhipu/Z.ai GLM via Vertex AI Model Garden) — same interface |
| 7 Intel | `pipeline/intel.py` | `LocalIOCClient` (known-bad set) | VirusTotal/AbuseIPDB (reuse Bantay `IntelClient`) |
| 8 IOCs | `pipeline/verdict.py` | Canonical IOC extraction | + push to Wazuh CDB / Redis maps |
| 9 Verdict | `pipeline/verdict.py` | Hard overrides + max-plus weighted scoring | (same) |
| 10 Report | `report.py` | Text report, Slack blocks, JSONL audit | + S3 evidence store |

Stages 5 and 7 are **pluggable via a Protocol interface** — the offline
providers and the production providers are interchangeable, so the pipeline
code never changes when you go live. That is the whole point: this core is
~70–80% of the production detection code.

## Scoring model (important)

- **Hard overrides** bypass weighting for high-confidence cases: threat-intel
  hit, sender/URL lookalike domain, banned attachment, and BEC VIP-impersonation
  (VIP-name spoof + gift-card/wire language co-occurring). These go straight to
  MALICIOUS.
- **Weighted composite** uses a *max-plus blend* (dominant signal + damped sum
  of the rest), not a plain average — so several independent moderate signals
  reinforce instead of being diluted toward zero by stages that correctly found
  nothing. Weights and thresholds live in `rules/weights.yaml`; tune them
  against your golden set before enabling enforcement.
- The AI stage only ever contributes a **weighted sub-score**. It cannot set
  the verdict directly — this is the prompt-injection containment guarantee for
  BSP examiners: a malicious email body cannot talk the model into an action,
  because the deterministic engine owns every decision.

## Wiring production providers

`BedrockProvider`, `GeminiProvider`, and `GLMProvider` (Stage 5) are all
already implemented in `pipeline/content_ai.py`, sharing one prompt/schema so
behavior is consistent across backends. All off by default — `run_pipeline()`
picks the content provider via `content_ai.get_default_provider()`, which
reads `PDAX_CONTENT_PROVIDER` (`heuristic` default / `bedrock` / `gemini` /
`glm` / `null`).

**Bedrock:**
```bash
export PDAX_CONTENT_PROVIDER=bedrock
export AWS_REGION=ap-southeast-1          # default if unset
export PDAX_BEDROCK_MODEL_ID=anthropic.claude-3-5-sonnet-20241022-v2:0   # default if unset
pip install boto3                          # optional dep, only needed for this provider
```
You need to **request model access for the chosen model in the Bedrock
console for ap-southeast-1** before first use (Bedrock gates each model per
account/region) — verify which Claude model IDs are actually enabled there.

**Gemini (Google AI Studio):**
```bash
export PDAX_CONTENT_PROVIDER=gemini
export PDAX_GEMINI_API_KEY=...            # or GEMINI_API_KEY — the SDK's own default env var
export PDAX_GEMINI_MODEL_ID=gemini-flash-latest   # default if unset — an alias, not a pinned version (pinned 2.5-flash/-pro both got retired within months; the "-latest" alias avoids re-hitting this)
pip install google-genai                   # optional dep, only needed for this provider
```
**Data-residency flag — do not skip:** this is the Google AI Studio developer
API, not Vertex AI. There is no region pinning and the data-processing terms
are weaker than an enterprise/regional backend would give you — email content
leaves PH jurisdiction to Google's consumer API surface. **Confirm DPO
sign-off under RA 10173 before pointing this at real employee/customer mail**;
this is exactly the scenario HANDOFF.md flagged when Bedrock was chosen
instead. If PDAX later gets Vertex AI access, that's the lower-risk path
(region-pinnable, enterprise data terms) — ask for it explicitly since the
plain API key is what's implemented today.

**GLM (via Vertex AI Model Garden MaaS):**
```bash
export PDAX_CONTENT_PROVIDER=glm
export PDAX_GLM_CREDENTIALS_PATH=/path/to/credentials.json   # a GCP service-account key (see below) — project_id is read from it automatically
export PDAX_GLM_MODEL_ID=zai-org/glm-4.7-maas   # default if unset — verify what's actually enabled in your Model Garden console; GLM-5/5.1 exist too
pip install openai google-auth              # optional deps — OpenAI-compatible client + service-account token refresh
```
Chosen specifically to escape Google AI Studio's free-tier rate limits, not
for GLM's model capabilities per se. Things to know, confirmed against the
real endpoint on 2026-08-04, not just cosmetic:
- **Region:** the documented MaaS path for GLM is a `locations/global`
  endpoint, not region-pinned — check in the GCP console whether GLM
  specifically supports regional pinning before assuming this carries the
  same in-region story that motivated Vertex AI over AI Studio in the first
  place.
- **Provenance:** GLM is developed by Zhipu AI (Z.ai), not Google — even
  served through Google's infrastructure, that's a distinct data-governance
  question from Google's own first-party Gemini model. Get this explicitly
  signed off, the same as the AI Studio decision was.
- **Credentials — RESOLVED:** `PDAX_GLM_CREDENTIALS_PATH` (or the standard
  `GOOGLE_APPLICATION_CREDENTIALS`) points at a GCP **service-account JSON
  key** (`gcloud iam service-accounts keys create`, or downloaded from the
  IAM console — `"type": "service_account"` in the file). That key itself
  doesn't expire, but `GLMProvider` mints a short-lived (~1hr) Vertex AI
  access token from it via `google-auth` and auto-refreshes before every
  call (`_ServiceAccountTokenProvider`, passed to `OpenAI(api_key=...)`,
  which accepts `str | Callable[[], str]`) — safe for a long-running
  gateway process, not just a one-shot script. A fixed `PDAX_GLM_API_KEY`
  string still works and takes precedence if set, for a backend that hands
  out a stable key instead of a service account.
- **Token budget:** confirmed live that `zai-org/glm-4.7-maas` is a
  reasoning model — it spends completion tokens on hidden chain-of-thought
  (`message.reasoning_content`) before its JSON answer; a real test email
  used ~1,400 completion tokens total. `GLMProvider`'s default `max_tokens`
  is 4000 to leave headroom for this — a lower value truncates mid-thought
  and the call degrades honestly (empty content) rather than erroring.

**All three providers:**
- Output is schema-constrained (Bedrock via forced tool-use, Gemini via
  `response_mime_type=json` + `response_schema`, GLM via
  `response_format={"type":"json_object"}` plus an explicit schema
  instruction in the prompt since field-level enforcement through this
  gateway is unconfirmed), validated with pydantic against a shared
  `_ContentAnalysis` model, with one repair retry on a schema violation. A
  persistent failure or a provider outage degrades honestly to a zero
  content sub-score (`status=degraded`) rather than raising — none of the
  three can sink the pipeline.
- The shared prompt explicitly treats the email body as untrusted data and
  instructs the model not to follow any instructions embedded in it — an
  attempt is itself surfaced as the `prompt_injection_attempt` finding.
- Model output only ever becomes `(score, findings, facts)`; `verdict.py` still
  owns every scoring decision, same guarantee as `HeuristicProvider`.

## Controlling AI-call volume at production scale (`PDAX_LLM_TRIAGE`)

Analyzing every single email with a paid/rate-limited AI provider doesn't
scale — most real mail is decisively clean or decisively bad from the free
stages alone (headers/sender/urls/attachments/intel + the regex
`HeuristicProvider`) and doesn't need an LLM call to confirm that. Set
`PDAX_LLM_TRIAGE=1` (default off) to make `run_pipeline()` cascade instead of
always calling the configured LLM provider:

1. Every email gets a free heuristic-only content pass first.
2. If that already produced a hard override, or the composite score isn't
   within `PDAX_LLM_TRIAGE_MARGIN` points (default 15) of the LOW/MALICIOUS
   thresholds, the heuristic result is kept as final — **no LLM call spent.**
3. Otherwise (the genuinely ambiguous middle), the real provider
   (`BedrockProvider`/`GeminiProvider`) is called and its result replaces the
   heuristic one.

This is **off by default** specifically so `analyze.py`'s interactive
workflow (force a specific provider, see what it says about *this* email)
never silently skips a call you explicitly asked for — it's meant for
production/gateway volume, not CLI debugging. The stage's `facts` (and the
CLI report / JSON audit record) record `triage_skipped_llm` or
`triage_escalated` so the decision is always auditable. The margin default
hasn't been calibrated against real production traffic — tune it against a
larger golden set once real volume is known.

`intel.py`'s real `IntelClient` (VirusTotal/AbuseIPDB via Bantay SOC) is not
wired yet — still `LocalIOCClient` today. Same injection point:

```python
from app.pipeline.runner import run_pipeline

result = run_pipeline(
    raw_bytes,
    source="gmail_api",                 # or "smtp_hold" in the gateway
    intel_client=BantayIntelClient(),
)
```

Implement `analyze(subject, body, context) -> (score, findings, facts)` for a
content provider and `check(domains, ips, urls, hashes) -> (hits, degraded)` for
the intel client. That's the entire contract.

## Layout

```
analyze.py              CLI
app/
  models.py             pydantic schemas (Verdict, StageResult, PipelineResult, IOCSet)
  parsed_email.py       stdlib email wrapper (urls, anchors, attachments, bodies)
  domainutils.py        registrable domain, homoglyph fold, bounded levenshtein
  report.py             text / Slack / JSONL renderers
  pipeline/
    headers.py sender.py urls.py attachments.py content_ai.py intel.py
    verdict.py           IOC extraction + scoring engine
    runner.py            orchestrator (safe per-stage error isolation)
rules/
  weights.yaml protected_domains.txt vip_names.txt
samples/                clean + phish + bec .eml
tests/
  test_core.py run_eval.py
```

## Next steps toward production

1. Grow `samples/` into the real golden set (defanged TMES quarantine + crafted
   PDAX-targeted lures + legitimate traffic) and tune `weights.yaml` until
   `run_eval.py` hits the Annex B targets.
2. ~~Implement `VertexProvider` and drop it in~~ — done as `BedrockProvider`
   (Claude on AWS Bedrock, ap-southeast-1); request model access in the
   Bedrock console, set `PDAX_CONTENT_PROVIDER=bedrock`, then re-run
   `run_eval.py` to confirm it beats the heuristic baseline before enabling.
3. Implement the real `IntelClient` (VirusTotal/AbuseIPDB via Bantay SOC) in
   `pipeline/intel.py` — currently still `LocalIOCClient`.
4. Wrap the same `run_pipeline` in the Gmail-API POC receiver (Annex B) and the
   SMTP hold consumer (Annex C, `hold_consumer.py` already imports it).
