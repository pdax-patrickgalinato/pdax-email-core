# CLAUDE.md

Guidance for Claude Code (or any future agent) working in this repo. See
`HANDOFF.md` for project history and the prioritized backlog — this file is
the durable reference; `HANDOFF.md` is the narrative.

## What this is

The transport-agnostic email-analysis core behind PDAX-PROP-SEC-001, PDAX's
plan to replace Trend Micro Email Security (TMES) with an in-house pipeline.
`run_pipeline(raw_bytes, source=...)` in `app/pipeline/runner.py` is the single
entry point called identically by:
- the CLI (`analyze.py`, `source="file"`) — how you develop/tune offline,
- the future Gmail-API POC (`source="gmail_api"`, monitor-only, Annex B),
- the future Postfix+Rspamd inline gateway (`source="smtp_hold"`, Annex C).

Runs **fully offline by default** — no AWS, no Gmail, no API keys required —
so detection logic can be developed and tuned against `.eml` files without any
external dependency. Enrichment providers (Stages 5 and 7) are opt-in via env
vars / constructor args, never required.

## Architecture invariant — read before touching `verdict.py` or any provider

**The AI/enrichment stages only ever contribute a weighted sub-score or a set
of red-flag tags. They never set the verdict directly.** `verdict.py` is the
sole owner of every MALICIOUS/SUSPICIOUS/LOW/CLEAN decision, via:
1. A short list of **hard overrides** (threat-intel hit, lookalike domain,
   banned attachment, BEC+VIP-impersonation combination) that bypass weighting
   entirely for high-confidence cases.
2. A **max-plus weighted composite** otherwise (dominant signal + damped sum of
   the rest — deliberately not a plain average; see "Detection lessons" in
   HANDOFF.md for why averaging burned a real BEC case).

This is the prompt-injection containment guarantee for BSP examiners: a
malicious email body cannot talk a content-AI provider into an action, because
the provider's return type is always `(score, findings, facts)` and the
deterministic engine downstream owns the decision. Any new provider (content
or intel) MUST preserve this — do not let model/API output write directly to
`result.verdict`.

Corollary for content providers specifically: the email body is attacker-
controlled untrusted data. Any provider that calls an LLM must treat prompt
injection attempts in the body as adversarial input to detect, not instructions
to follow (see the shared `_SYSTEM_PROMPT` in `content_ai.py`, used by both
LLM providers, for the pattern — flag the attempt as a finding, don't comply
with it).

## Providers are pluggable via `typing.Protocol`

- `content_ai.ContentProvider.analyze(subject, body, context) -> (score, findings, facts)`
  — `NullProvider` (degraded no-op), `HeuristicProvider` (offline default,
  keyword/regex), `BedrockProvider` (Claude via AWS Bedrock, ap-southeast-1),
  `GeminiProvider` (Gemini via Google AI Studio API key — **no region pinning,
  needs DPO sign-off under RA 10173 before real mail**, see the class
  docstring), `GLMProvider` (Zhipu/Z.ai GLM via Vertex AI Model Garden's
  OpenAI-compatible MaaS endpoint — chosen to escape AI Studio's rate
  limits; **endpoint is `locations/global` not region-pinned, third-party
  model provenance distinct from Google's own Gemini — still flagged, don't
  assume resolved**. Credential format *is* resolved as of 2026-08-04: a
  GCP service-account JSON key via `credentials_path`/
  `PDAX_GLM_CREDENTIALS_PATH`, auto-refreshed by
  `_ServiceAccountTokenProvider` — confirmed working against the real
  endpoint, see the class docstring and HANDOFF.md's later 2026-08-04
  entry). All three LLM providers share one `_SYSTEM_PROMPT` and one
  `_ContentAnalysis` pydantic schema — tune the analysis approach in one
  place, not per-provider. Selected via `PDAX_CONTENT_PROVIDER`
  (`heuristic`/`bedrock`/`gemini`/`glm`/`null`), off by default.
- `intel.IntelClient.check(domains, ips, urls, hashes) -> (hits, degraded)` —
  `LocalIOCClient` (offline default, checks a provided known-bad set). Real
  VirusTotal/AbuseIPDB client (Bantay SOC) not yet wired — still a stub, and
  the single highest-leverage thing left to build (it's a hard override).

Selection happens in `runner.run_pipeline()` via `content_provider=`/
`intel_client=` kwargs, or the defaults returned by
`content_ai.get_default_provider()` / a `LocalIOCClient()`. Never hardcode a
provider choice elsewhere — route new call sites through these.

**LLM-call volume control:** `PDAX_LLM_TRIAGE=1` makes `run_pipeline()`
cascade instead of always calling the configured LLM provider — a free
`HeuristicProvider` pass runs first, and the real provider is only called
for the ambiguous middle (`_should_escalate()` in `runner.py`: skip if a
hard override already fired, or the heuristic-only score isn't within
`PDAX_LLM_TRIAGE_MARGIN` of the LOW/MALICIOUS thresholds). Off by default —
don't assume it's active. This exists because per-call AI providers (Google
AI Studio free tier especially) can't sustain analyzing every production
email; see HANDOFF.md's 2026-08-03 entry for the full reasoning and the
other volume options considered but not built (caching, Vertex AI, Bedrock
Provisioned Throughput, self-hosted model).

## Environment constraint

The user's macOS fleet's **system** Python is 3.9 (JumpCloud-managed, not a
heavy CLI user) — but system Python 3.9 reached end-of-life, and its
dependencies (`google-auth` via `google-genai`, notably) started warning
loudly about it. As of 2026-08-02, the **dev `.venv` runs on Homebrew Python
3.12** instead (`brew install python@3.12`; already present on the user's
machine at `/opt/homebrew/bin/python3.12`) — actively supported through
October 2028, no more EOL warnings.

**The codebase itself is still kept 3.9-compatible on purpose**, even though
nothing currently runs it on 3.9: every file must still parse under Python
3.9 (`from __future__ import annotations` plus PEP 585 generics like
`list[str]` work fine at 3.9 runtime; avoid `match` statements, `X | Y`
union syntax outside annotations, `tomllib`, etc.). This is a deliberate,
conservative choice, not an oversight — it keeps the code portable to
wherever it runs next (a future gateway server, another teammate's older
setup) without forcing that decision now. If the user ever confirms nothing
downstream needs 3.9 anymore, this constraint can be dropped and the
`ast.parse(..., feature_version=(3,9))` gate relaxed — don't do that
unilaterally, ask first, the same way the interpreter upgrade itself was a
user decision, not an assumed one. Verify with the compatibility check below
before calling any change done.

## Definition of done for any change

```bash
source .venv/bin/activate
python3 tests/test_core.py                 # unit tests
python3 tests/test_content_ai_bedrock.py    # BedrockProvider tests (mocked, offline)
python3 tests/test_content_ai_gemini.py     # GeminiProvider tests (mocked, offline)
python3 tests/test_content_ai_glm.py        # GLMProvider tests (mocked, offline)
python3 tests/test_llm_triage.py            # LLM-call cascade/volume-control tests (mocked, offline)
python3 tests/run_eval.py samples/          # precision/recall on the sample corpus — must stay FP=0
python3 -c "import ast,pathlib;[ast.parse(p.read_text(),feature_version=(3,9)) for p in pathlib.Path('.').rglob('*.py') if '.venv' not in str(p)]"  # 3.9-safe
```

## Conventions already established in this codebase

- No docstring bloat: module-level docstrings explain the *why* of a stage in
  a few lines; function/class docstrings only when something is non-obvious.
- New detection rules from a real missed-detection get generalized (see
  "Detection lessons already learned" in HANDOFF.md) and verified against
  legitimate traffic before merging — a rule that isn't checked against a
  clean sample is a future false positive.
- `rules/weights.yaml` and `rules/*.txt` are data, not code — tune thresholds
  there, don't hardcode scores in Python.
- Every stage function returns a `StageResult` (see `app/models.py`) and the
  runner wraps every stage call in `safe()` so one broken stage never sinks
  the whole pipeline — new stages must follow this (return a degraded/error
  `StageResult`, never raise out of `run()`).
