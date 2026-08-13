# HANDOFF — where we are and what's next

Companion to `CLAUDE.md`. This narrates the project history and gives the
next agent a prioritized backlog. Originally written at the point the user
moved from the web chat into Claude Code; updated 2026-08-01 after the first
Claude Code session implemented the real content-AI provider.

## The user

Pat / Ronald Galinato — Cyber Defense team at **PDAX**, a BSP-supervised VASP
(crypto exchange) in the Philippines. ~13 years IT background, strong on
security operations, comfortable with concepts but **not a heavy CLI user** —
keep tooling forgiving and explanations concrete. Environment elsewhere:
Wazuh SIEM, AWS ap-southeast-1, Google Workspace, JumpCloud-managed macOS fleet.
Communicates in English here; Taglish internally.

The broader goal: **build an in-house email security platform to replace Trend
Micro Email Security (TMES).** A real phishing email in testing had already
passed through TMES (it carried a `clicktime.trendmicro.com` rewrite wrapper)
and was still malicious — good ammunition for the business case.

## How this repo came to be (chronological)

1. Started from a "Phishing Analysis" infographic (12 steps). Mapped it to
   PDAX's existing stack (Rspamd, Sublime, Gemini, Python/FastAPI orchestrator).
2. Wrote **Annex A** — a 10-stage pipeline spec (headers → sender → URL →
   attachment → content AI → brand/visual → threat intel → IOC → verdict → report).
3. Wrote **Annex B** — a post-delivery Gmail-API POC (monitor-only, no MX
   change, ~4 weeks, <$75), which detects and reports but never blocks.
4. Wrote **Annex C** — an inline **Postfix + Rspamd** SMTP gateway that runs
   the pipeline PRE-delivery across three enforcement points (SMTP connection,
   end-of-DATA milter, post-queue HOLD) and can reject/quarantine. Includes a
   real config skeleton: `main.cf`, `master.cf`, Rspamd Lua lookalike rule,
   `hold_consumer.py` (imports `run_pipeline`), `map_writer.py`.
5. Realized every doc referenced a `run_pipeline()` that didn't exist — so we
   **built this core** (the thing you're reading). It runs offline, tested live.
6. User is on macOS system Python 3.9 — made the whole codebase 3.9-safe.
7. Iterative real-world hardening driven by the user feeding real `.eml` files
   (see "Detection lessons" below).
8. **2026-08-01, first Claude Code session:** confirmed the offline baseline
   still holds (6/6 unit tests, precision/recall 1.00 on samples, 3.9-safe),
   then implemented P0 item 2 — see "What changed this session" below. Also
   wrote this file and `CLAUDE.md` into the repo itself (previously they only
   existed as pasted context from the web chat, not committed anywhere).

Annexes A/B/C and the gateway config are **separate files** the user has from
the web chat; they are NOT in this repo. If you need them, ask the user to drop
them in `docs/`. Their essence is captured in `CLAUDE.md` + this file.

## What changed this session (2026-08-01)

Implemented **P0 item 2 — the real `ContentProvider`** in
`app/pipeline/content_ai.py`:

- User chose **AWS Bedrock (ap-southeast-1)** over local-model/Gemini for the
  data-residency story under RA 10173 — they're already in this AWS account.
- `BedrockProvider` calls Claude via Bedrock's **Converse API with forced
  tool-use**, so output is always schema-constrained JSON, never free text —
  validated with pydantic, one repair retry on a schema violation, honest
  degrade-to-zero (not a raise) on persistent failure or an AWS outage.
- The user did **not** have the original "7-phase EML analysis" Gemini prompt
  handy, so the system prompt was **drafted fresh** this session (sender-claim
  plausibility, urgency, credential harvesting, BEC/financial, brand
  impersonation, language anomalies, overall intent). It has not been
  compared against the original prompt's phrasing/thresholds — if the original
  turns up later, diff it against `_SYSTEM_PROMPT` in `content_ai.py` and
  reconcile, since the original may encode tuning the user already validated.
- Explicit prompt-injection containment: the email body is framed as
  untrusted data in the prompt; an injection attempt is itself surfaced as a
  `prompt_injection_attempt` finding rather than followed.
- **Off by default** — gated behind `PDAX_CONTENT_PROVIDER=bedrock` (default
  `heuristic`, matching the "gate behind a flag, keep offline default" posture
  used elsewhere). `boto3` stays an optional/commented dependency, imported
  lazily so the offline core never requires it.
- 5 new offline unit tests in `tests/test_content_ai_bedrock.py` (mocked
  Bedrock client — no real AWS calls) covering the happy path, repair-retry
  recovery, persistent-failure degradation, missing-tool-call handling, and
  the `PDAX_CONTENT_PROVIDER` selector.
- README updated with the env-var wiring instructions and a note that the
  chosen model must have **access explicitly granted in the Bedrock console
  for ap-southeast-1** before first real use.

**Not yet done, and worth doing before relying on this in production:**
- Nobody has run `BedrockProvider` against a real AWS account yet — this
  session had no AWS credentials available. First real run should re-check
  `tests/run_eval.py samples/` with `PDAX_CONTENT_PROVIDER=bedrock` and compare
  against the `HeuristicProvider` baseline (precision/recall should not regress).
- `PDAX_BEDROCK_MODEL_ID` defaults to `anthropic.claude-3-5-sonnet-20241022-v2:0`
  — verify this ID is actually enabled for the account/region; Bedrock model
  access is granted per model per region and the default may need to change.
- The finding vocabulary (`_KNOWN_FINDINGS` in `content_ai.py`) only guarantees
  `bec_pattern` is reachable for the existing BEC+VIP hard override in
  `verdict.py`. If new hard overrides get added that key off other exact
  finding strings, make sure the Bedrock prompt's preferred-tags list is kept
  in sync (it's the single source of truth already interpolated into the
  prompt — don't duplicate the list elsewhere).

## What changed 2026-08-02 — real-world validation + second content provider

**Security review (SAST + dependency check):** `pip-audit` and `bandit` both
came back clean on the actual project deps/code. Found and fixed one real
issue by manual trace, not tooling: `report.py`'s `text_report()`/
`slack_blocks()` printed attacker-controlled `From`/`Subject` verbatim — a
crafted MIME-encoded Subject can decode to raw ANSI escape bytes (proved this;
could spoof the printed verdict line in an analyst's terminal, CWE-150) and an
unescaped Subject like `<!channel>` would render as a literal Slack
channel-wide ping. Fixed with `_sanitize()` (strip control chars, flatten
embedded CR/LF) and `_slack_escape()`, applied everywhere those fields reach
an output surface.

**Security review round 2** (full repo, all 18 `.py` files, after
`GeminiProvider` was added): `bandit` across the whole tree — only the 2
known-benign findings above, plus expected `assert`-in-tests noise. Checked
the optional AI-provider dependencies specifically, in an isolated scratch
venv (neither `boto3` nor `google-genai` is installed in the project's own
`.venv`):
- Confirmed `google-genai` supports Python 3.9 (`Requires-Python: >=3.9` in
  its own package metadata) — no compatibility surprise.
- `requests` (transitive via `google-genai`): PYSEC-2026-2275, a predictable
  temp-file-reuse issue requiring a local attacker with filesystem write
  access already — low severity, and trivially fixable by pinning
  `requests>=2.33.0` whenever `google-genai` is actually installed.
- `urllib3` (transitive via `boto3`→`botocore`): multiple real CVEs
  (unbounded HTTP-decompression resource exhaustion; a cross-origin
  redirect header-leak). **Structural, not fixable here**: confirmed via
  `botocore`'s own dependency metadata that it hard-pins
  `urllib3 (<1.27,>=1.25.4)` for any Python below 3.10, and 1.26.20 (the
  vulnerable version) is the last release ever published in that branch —
  no backported fix exists. Since this project stays on Python 3.9
  deliberately (see Environment constraints), `boto3`/Bedrock is
  permanently capped there. Real-world exploitability is low (requires a
  malicious response from the Bedrock endpoint itself, a trusted
  first-party AWS service) — documented as an accepted, monitored risk,
  not an action item.
- Wrote up all of this plus the project overview into three checkpoint
  reports for the user: `docs/reports/TECHNICAL_REPORT.md`,
  `NONTECHNICAL_REPORT.md`, `TLDR_REPORT.md`.

**Real-world validation against actual phish** (`samples/agora.eml`,
`samples/phish_wooga_esign_oauth_bec.eml`, the latter confirmed phishing via
an external analyzer's ground-truth writeup — ticket INC-260729-045). The
`wooga` case was a genuine miss: **LOW (41.2) when it should have been
MALICIOUS.** Root-caused and fixed with three new generalized rules (verified
against all existing samples first, FP stayed at 0):
- `sender.py` — `BRAND_DOMAINS` dict + `brand_impersonation_display_name:<brand>`
  (+40): a display name naming a known e-sign/file-share brand (ShareFile,
  DocuSign, Adobe Sign, Dropbox, PandaDoc, OneDrive/SharePoint, WeTransfer)
  whose sending domain has no relationship to that brand. Distinct from the
  existing VIP-name-spoof check — the borrowed trust here is the *brand's*,
  not an individual's.
- `urls.py` — `_OAUTH_AUTHORIZE_PATH` + `url_oauth_state_email_exposure`
  (+35): an OAuth/OIDC `/authorize` URL (fires regardless of host reputation —
  `login.microsoftonline.com` is fully legitimate) carrying a plaintext victim
  email in `state`. Legitimate apps use an opaque token there, never PII — the
  shape itself is the tell (consent-phish/recon), not the domain.
- `content_ai.py` `HeuristicProvider.PADDING` + `content_padding_evasion`
  (+20): 12+ consecutive blank/whitespace-only lines. This is the "oversized
  whitespace pad hiding an injected, often-legitimate reused thread beneath
  the actual ask" evasion technique — checked all 6 pre-existing samples cap
  out at 1–2 consecutive blank lines first, so the margin is wide.
- Bug fix, `content_ai.py` `run()`: this email's `text/plain` MIME part
  itself contained raw unstripped HTML (a real mailer quirk) — tags were only
  stripped on the `html_body()` fallback path. Now always stripped regardless
  of source; matters even more once an LLM provider is actually in use, since
  markup soup was burning its context budget on CSS/divs instead of the lure.
- `phish_wooga_esign_oauth_bec.eml` is now a **permanent regression sample**
  (renamed from `wooga.eml` for the `run_eval.py` label convention).
- `agora.eml` **ground truth is still unconfirmed** — pipeline currently
  scores it CLEAN (the TrendMicro `clicktime`-wrapped redirect resolves back
  to the sender's own domain, which is the same pattern legitimate trackers
  use). Get a verdict from the user before treating either the CLEAN score or
  any rule change around it as correct.

**Second content provider — `GeminiProvider`** (`content_ai.py`), added
alongside `BedrockProvider` (kept, not replaced — both are legitimate options
behind the same `PDAX_CONTENT_PROVIDER` switch):
- User's paid access is confirmed as **Google AI Studio API key** (not Vertex
  AI). **Flagged explicitly per the "flag it, don't silently route bodies to
  a third party" rule**: no region pinning, weaker data-processing terms than
  Vertex AI — email content leaves PH jurisdiction to Google's consumer API
  surface. **DPO sign-off under RA 10173 is still needed before real mail.**
  If Vertex AI access shows up later, that's the lower-risk path (region-
  pinnable, enterprise terms) — ask for it explicitly, since the plain API
  key is what's implemented.
- Shares the exact same `_SYSTEM_PROMPT` and a renamed shared
  `_ContentAnalysis` pydantic schema with `BedrockProvider` (was
  `_BedrockAnalysis`) — one prompt/schema, two thin provider classes, so
  behavior stays consistent across backends and there's only one place to
  tune the analysis approach.
- Structured output via `response_mime_type=json` + `response_schema`
  (Gemini's equivalent of Bedrock's forced tool-use), same repair-retry-once
  and honest-degrade-on-failure contract.
- **User decision on API key project/tier (2026-08-02):** while setting up
  the Google AI Studio key, the user generated it under the auto-created
  "Default Gemini Project" rather than a specific billed GCP project — this
  is very likely the **free tier**, not the paid subscription PDAX actually
  has. This matters beyond the region/enterprise-terms flag already noted
  above: free-tier Gemini API usage is subject to Google's terms allowing
  submitted content to be used to improve their products (i.e. it may be
  used for model training, not just processed and discarded). This was
  explained to the user explicitly, including the distinction between
  synthetic golden-set samples (low stakes) vs. real captured email like
  `agora.eml`/`phish_wooga_esign_oauth_bec.eml` (contains a real PDAX
  employee address, `kenneth.chua@pdax.ph`). **The user's explicit,
  informed decision: proceed with real samples too, accepting the free-tier
  risk.** This does not remove the earlier RA 10173/DPO sign-off flag — it
  makes it more urgent, not less. If a future session finds Gemini being
  used against real mail without a documented DPO sign-off, that's the
  gap to close, not a new decision to make silently.
- **Model default went through two rounds of real-API-confirmed churn —
  now on an alias, not a pinned version.**
  1. `gemini-2.5-pro` → real `429 RESOURCE_EXHAUSTED ... limit: 0 ...
     FreeTier`: the free tier (no billing attached, "Default Gemini
     Project") grants **zero** quota for `-pro` models at all.
  2. Switched to `gemini-2.5-flash` → real `404 NOT_FOUND: This model
     models/gemini-2.5-flash is no longer available to new users`, within
     the same session. Note: `client.models.list()` **still lists**
     `gemini-2.5-flash`/`gemini-2.5-pro` as available — list-inclusion does
     NOT mean the model is actually invocable for this account. Don't trust
     it alone; a real `generate_content` call is the only real test.
  3. **Now defaults to `gemini-flash-latest`** — an alias Google maintains
     to always point at their current recommended flash-tier model,
     specifically to avoid this exact churn. The account's full available
     list (via `client.models.list()`, 2026-08-02) showed the live
     generation has moved to **Gemini 3.x** (`gemini-3.6-flash`,
     `gemini-3.5-flash`, `gemini-3.1-flash-lite`, `gemini-3-pro-preview`,
     etc.) — my knowledge cutoff is January 2026 and clearly can't track
     this, so don't hardcode a specific version off this note either; if a
     pinned version is ever needed instead of the alias (e.g. for
     reproducibility), re-run `client.models.list()` fresh first.
  4. If PDAX later gets a billed project, `gemini-pro-latest` is the
     equivalent alias for deeper/costlier analysis, selectable via
     `PDAX_GEMINI_MODEL_ID`.
- **First successful real Gemini analysis, confirmed 2026-08-02** (against
  `samples/agora.eml`, with the user's real free-tier key): `content_ai`
  came back `status=ok` (not degraded) with real findings
  (`content_padding_evasion, credential_request, urgency_language,
  brand_impersonation`, sub_score 85.0), moving the composite verdict from
  CLEAN to **SUSPICIOUS (45.0)**. This is independent signal worth weighing
  when `agora.eml`'s ground truth finally gets confirmed — Gemini disagreed
  with the heuristic-only baseline in a specific, explainable way.
- **Fixed noisy-but-harmless SDK warning** surfaced by that first real run:
  `response.text` (google-genai's convenience accessor) calls
  `logging.warning(...)` — not an exception — whenever a "thinking" model
  attaches a `thought_signature` part alongside the text answer, which
  newer Gemini models do by default. It printed
  `"Warning: there are non-text parts in the response..."` to the terminal
  on every real call, easily mistaken for an actual error (the user did).
  Fixed by adding `GeminiProvider._extract_text()`, which walks
  `response.candidates[0].content.parts` directly and concatenates only
  real (non-thought) text parts, sidestepping the warning entirely —
  verified against an actual `types.GenerateContentResponse` built with a
  mixed thought/text part list, not just the mocked tests.
- `google-genai` stays optional/lazily-imported, same posture as `boto3`.
- **`report.py` gap found and fixed while diagnosing the above:** a degraded
  stage's actual error (bad key, quota, outage) was captured internally but
  never surfaced anywhere in `text_report()`/`audit_record()` — you'd just
  see "degraded" with no way to tell why. Both now include a sanitized
  `reason:`/`error` field pulled from `StageResult.facts["error"]` when
  present. This is what made the free-tier quota message visible at all.
- 5 new offline unit tests in `tests/test_content_ai_gemini.py` (mocked
  client, no real Google API calls) — happy path, repair-retry recovery,
  persistent-schema-failure degradation, empty-response degradation,
  malformed-JSON degradation. Also extended the env-var selector test in
  `test_content_ai_bedrock.py` to cover `gemini`.
- **Neither Bedrock nor Gemini has been run against a real API yet** — no
  credentials for either were available this session. First real run of
  either should re-check `tests/run_eval.py samples/` with
  `PDAX_CONTENT_PROVIDER` set and compare against the `HeuristicProvider`
  baseline before trusting it.

**Note on this file's own history:** the user separately pasted an *original*
`CLAUDE.md` from the web-chat phase that described capabilities never
actually implemented in any shipped copy of this code (an `explain.py` tool,
13 golden-set samples, a `credential_harvest_pattern` hard override,
structural HTML/attachment/URL checks) — confirmed by diffing against an
untouched backup copy and the original `pdax-email-core.zip`, both predating
this session and both already lacking those things. That document was
aspirational, not a regression to fix against. The user chose to keep this
`HANDOFF.md`/`CLAUDE.md` pair (grounded in actual code) as-is rather than
merge it in.

## Detection lessons already learned (don't re-learn these)

- **Averaging dilutes signals.** A BEC gift-card email first scored CLEAN
  because many clean stages averaged down two strong signals. Fixed with the
  max-plus blend + combination hard-overrides. Keep combinations as overrides.
- **Open-redirect abuse.** A real phish hid `td_redirect=https://artistgallery.pk/...`
  inside a legitimate `treasuredata.com` tracker URL. Surface-domain checks saw
  a clean analytics domain and passed. Fixed with recursive
  `unwrap_embedded()` in `urls.py` that pulls targets out of ~20 redirect
  params and scores them on their own merits. The real payload domain now lands
  in IOCs. **Legitimate trackers redirect to the sender's OWN domain** — that's
  the distinction that keeps false positives at zero; don't flag on the presence
  of a redirect param, flag on an unrelated target.
- **MIME-encoded subjects.** `=?utf-8?b?...?=` subjects were opaque to keyword
  checks — an evasion. Header decoding now in `parsed_email.header()`.
- **Compromised legitimate senders pass SPF/DKIM/DMARC.** Auth checks
  structurally cannot catch phishing sent from a hacked real account (e.g. a
  hijacked non-profit). The signal must come from content/URL analysis. Don't
  weight auth as decisive.
- **Phishing is a combination of moderate signals**, rarely one smoking gun.
  Free-hosting + pretext language; form-builder + urgency; image-only body +
  offbrand link. The `credential_harvest_pattern` override encodes this.
- **The user's misses are the roadmap.** Each real CLEAN-should-be-malicious
  produced a general rule (verified against legit controls), not a one-off patch.

## Prioritized backlog

### P0 — Wire real capability into the remaining stub stage

1. ~~Real `ContentProvider`~~ — **done this session**, see above.
   `Real `IntelClient` (`app/pipeline/intel.py`)** still outstanding. Reuse
   PDAX's existing Bantay SOC intel clients (VirusTotal + AbuseIPDB) — the
   user already has API keys and a client library for those from prior work.
   Implement `check(domains, ips, urls, hashes) -> (hits, degraded)`. Cache
   with a TTL (SQLite or Redis) and respect free-tier rate limits. An intel
   hit is already a hard override, so this immediately upgrades detection.
   Set `degraded=True` on provider outage so scoring weights down gracefully.

### P1 — Make tuning real
2. **Grow the golden set.** 6 curated samples is a smoke test, not a
   benchmark. Have the user export defanged real phish from TMES quarantine +
   real legitimate PDAX traffic. Target dozens of each. `run_eval.py` already
   computes precision/recall and gates on FP=0.
3. **Per-rule attribution in eval.** Extend `run_eval.py` to report which
   flags fired on false negatives / false positives, so tuning is data-driven.
4. **Confusion-cost awareness.** For a VASP, a missed BEC costs more than a
   false-positive quarantine costs. Consider surfacing the tradeoff when tuning
   thresholds in `weights.yaml`.
5. **Validate `BedrockProvider` against real traffic** once AWS credentials
   are available in this environment — see "Not yet done" above.

### P2 — Enrichment stages that are currently static
6. **Live URL analysis** (`urls.py`): optional redirect-following + TLS cert
   inspection from an isolated egress path (Annex C requires this be a separate
   NAT/IP, never corporate egress; for the POC a guarded `httpx` HEAD-first is
   fine). Gate behind a flag; keep offline default.
7. **Attachment deep parse** (`attachments.py`): `oletools` for macros,
   `pdfid`/`pikepdf` for PDF actions, recursive archive unpack with caps. Add VT
   **hash lookup only** (never upload PDAX documents to public sandboxes — RA
   10173).
8. **Stage 6 visual/brand analysis** (not yet built): Playwright render of the
   final URL + LLM-vision brand comparison. Conditional trigger (only on
   lookalike/suspicious URLs) to bound cost. This is the one designed stage with
   no code yet.

### P3 — Transport shells (only after detection is trusted)
9. **POC receiver (Annex B):** FastAPI + Gmail `users.watch` → Pub/Sub push →
   `run_pipeline(source="gmail_api")` → label + Slack, monitor-only. Remember
   Gmail watches expire every 7 days (renewal task + failure alert).
10. **Gateway (Annex C):** in-repo now — `rules/disposition.yaml` maps
    verdict→DELIVER/LOG/QUARANTINE/REJECT; `app/disposition.py` +
    `EnforcementClient` (shadow default / local quarantine spool);
    `gateway/hold_consumer.py` runs `run_pipeline(source="smtp_hold")` then
    applies enforcement. Still lab/filesystem only — wire Postfix HOLD +
    real RELEASE/550 adapter after shadow-mode FP≈0 (a 550 loses mail; a
    quarantine is reversible). `allow_reject_on_malicious` stays false.

## Definition of done for any change

```bash
source .venv/bin/activate
python3 tests/test_core.py                 # unit tests
python3 tests/test_content_ai_bedrock.py   # BedrockProvider tests (mocked)
python3 tests/run_eval.py samples/         # FP=0, ideally FN=0
python3 -c "import ast,pathlib;[ast.parse(p.read_text(),feature_version=(3,9)) for p in pathlib.Path('.').rglob('*.py') if '.venv' not in str(p)]"  # 3.9-safe
```

## First thing to do in a new session

Get it running and confirm the baseline, then check this backlog for the next
open item:

```bash
source .venv/bin/activate
pip install -r requirements.txt
python3 tests/test_core.py
python3 tests/test_content_ai_bedrock.py
python3 tests/run_eval.py samples/     # expect precision 1.00 recall 1.00
python3 analyze.py samples/phish_open_redirect.eml   # see the diagnostic output
```

The next highest-value item is the **real `IntelClient`** (P0 #1 above) — it's
a hard override, so it has the same outsized effect on accuracy that
`BedrockProvider` was meant to have, and the interface already exists in
`app/pipeline/intel.py`.

## What changed 2026-08-02 (cont'd) — report readability

User feedback after the first real Gemini run: "I can't say if it is
malicious or not" — the report showed machine tags (`brand_impersonation`,
`content_padding_evasion`) and a bare score with no way to judge confidence
or understand what was actually detected. Fixed in `app/report.py`:

- **`_FLAG_DESCRIPTIONS` / `_FLAG_PREFIX_DESCRIPTIONS` / `_describe_flag()`**
  — a human-readable one-line translation for every flag any stage can
  produce (grepped exhaustively from `flags.append(...)`/`findings.append(...)`
  calls across all `pipeline/*.py`, not guessed). Unrecognized future tags
  still get a readable fallback (underscore→space, capitalized) rather than
  silently rendering blank.
- **The AI provider's `summary` field is now actually shown.** Both
  `BedrockProvider` and `GeminiProvider` compute a one/two-sentence rationale
  on every real call — it was being thrown away. Now surfaced as an
  "AI assessment:" line in `text_report()` and an `ai_summary` field in
  `audit_record()`'s JSON.
- **Threshold margin.** `PipelineResult` gained a `thresholds` field
  (populated in `verdict.py`'s `score_and_verdict()`), so the verdict line
  now shows e.g. "25.0 points below MALICIOUS (70), 0.0 above SUSPICIOUS
  (45)" instead of a bare, context-free score.
- `audit_record()`'s JSON `reasons` field changed shape — from a flat list
  of tag strings to `[{"tag":..., "description":...}]` — with the raw tags
  preserved separately as `reason_tags` for anything that wants them without
  re-parsing. Nothing in this repo depended on the old shape (checked before
  changing it), but the not-yet-built gateway/POC consumers should use
  `reason_tags` if they want the old flat-list behavior.

## What changed 2026-08-02 (cont'd) — IOC extraction was structurally incomplete

User ask: "include all the important IP addresses, malicious domain, email
and domain reputation." Tracing this turned up real gaps, not just missing
presentation — `IOCSet.ips` existed in the model but **nothing ever
populated it**, and `intel.py` hardcoded `client.check(domains, [], ...)`,
meaning IP-based threat-intel matching was structurally impossible
regardless of what an `IntelClient` implementation supported.

- **`parsed_email.py`**: new `originating_ips()` (public IPv4s from the
  `Received:` header chain, filtered via stdlib `ipaddress` to drop
  private/loopback/link-local/reserved hops — a mail gateway's own internal
  relay is noise, not an indicator) and `authenticated_relay_senders()`
  (parses `Authenticated sender: x@y` out of `Received:` headers). Verified
  against `phish_wooga_esign_oauth_bec.eml`'s real header chain — extracted
  `98.159.234.151`, `157.7.104.36`, `18.208.22.109` and correctly dropped
  `192.168.197.50` (TrendMicro's internal Postfix hop), plus
  `info@transfer.lolipop.jp` as the relay account — **this matches the
  external analyst's ground-truth report for this exact email almost
  line-for-line**, independently confirming both the original ground truth
  and this extraction logic.
- **`urls.py`**: IP-literal URL hosts were being run through
  `registrable_domain()` and silently miscategorized as a domain IOC (e.g.
  "192.168.1.1" → "1.1", a meaningless string). Now routed to `rec["ip"]`
  instead; added `url_redirect_to_ip` as its own flag when an embedded
  redirect's real target is a raw IP (this used to accidentally
  half-work via the same garbage-string bug, so this is a correctness fix,
  not new behavior — verified it doesn't regress anything already scored).
- **`verdict.py`'s `extract_iocs()`**: now also pulls Return-Path/Reply-To/
  Message-ID domains (computed by the headers stage, previously discarded),
  the new IP sources above, and authenticated relay senders.
- **`intel.py`**: `ips` parameter to `IntelClient.check()` is now actually
  populated (URL IP-literals + Received-chain IPs) instead of hardcoded
  `[]`. Any `LocalIOCClient` configured with `bad_ips` can now actually
  match something — this was silently dead code path before.
- **`models.py`**: `IOCSet` gained `authenticated_relay_senders`. `ips` was
  already there but dead.
- **`report.py`**: new `_ioc_context()` builds a per-IOC annotation dict
  from signals this analysis *already computed* (sender lookalike/brand
  impersonation, Return-Path/Reply-To divergence, URL lookalike/redirect/
  OAuth-exposure findings, intel hits) — deliberately **not** a live
  reputation/intel lookup, and labeled as such in both `text_report()` and
  `audit_record()`'s JSON, since presenting rule-based context as if it were
  live reputation data would violate this project's own "don't overstate
  capability" rule. IOCs are now printed one-per-line with `[context]` when
  flagged, rather than a flat Python-list repr.
- Real threat-intel reputation (VirusTotal/AbuseIPDB) is still the
  outstanding P0 item in `intel.py` — this session's work makes that
  integration *more* valuable once built (IPs now actually reach it), it
  doesn't replace the need for it.

## What changed 2026-08-02 (cont'd) — the "non-text parts" warning came back

The earlier fix (`GeminiProvider._extract_text()`, which walks
`response.candidates[...].content.parts` directly instead of using
`response.text`) only stopped **our own code** from triggering the
"Warning: there are non-text parts in the response..." message a second
time. It did NOT stop the first one: confirmed via `inspect.getsource()`
that `google-genai`'s `GenerateContentResponse.parsed` field is
**auto-computed inside the SDK's own `generate_content()` call** whenever
`response_schema` is set (which we always set — that's how structured
output works) — it calls `self._get_text(warn_property='parsed')`
internally, before control even returns to our code. There's no way to
avoid triggering this from the calling side; the config that causes it
(`response_schema`) is required for the whole schema-constrained-output
design to work at all.

Fixed at the actual source: `GeminiProvider._get_client()` now does
`logging.getLogger("google_genai.types").setLevel(logging.ERROR)` before
constructing the client — confirmed via a real `types.GenerateContentResponse`
object (mixed thought/text parts) that the warning fires before this line
and is silent after. Two warnings in one run = one schema-validation retry
happened (2 real API calls) — informational, not a sign of two separate
bugs.

## What changed 2026-08-02 (cont'd) — dev venv moved off EOL Python 3.9

`google-auth` (a `google-genai` dependency) started warning on every run
that Python 3.9 is past end-of-life and will only get best-effort critical
fixes going forward. Asked the user how to handle it rather than just
picking a direction, since this directly touches the 3.9 constraint that's
been load-bearing all session — **user chose to actually upgrade**, not
just suppress the warning.

- Found Homebrew Python 3.12 already installed on the user's machine
  (`/opt/homebrew/bin/python3.12`, EOL October 2028). Rebuilt `.venv` on it:
  `rm -rf .venv && /opt/homebrew/bin/python3.12 -m venv .venv`, reinstalled
  `requirements.txt` + `google-genai`. Confirmed `import google.auth`
  prints nothing now (was warning before). Full suite re-verified on the
  new interpreter: 16 tests + eval, still precision/recall 1.00/1.00, no
  regressions.
- **Scope decision, not asked separately (low-stakes/reversible so proceeded
  with the conservative default): the codebase itself stays 3.9-compatible**
  even though nothing runs it on 3.9 anymore. The `ast.parse(...,
  feature_version=(3,9))` gate in the definition-of-done is unchanged. This
  keeps the code portable to wherever it runs next (a future gateway
  server, another teammate's older machine) without deciding that now. If a
  future session wants to drop this and use newer syntax (`X | Y` unions,
  `match`, etc.), that's a real decision to bring back to the user, not
  something to just do because the dev venv happens to be newer.
- Updated `MACOS-SETUP.md` and `QUICKSTART.md` so a fresh setup uses
  `/opt/homebrew/bin/python3.12` instead of plain `python3` — otherwise the
  next person (or a wiped `.venv`) silently regresses back to system 3.9
  and the warning returns.

## What changed 2026-08-03 — dashboard findings fidelity + LLM-call triage

**Dashboard (`dashboard/index.html`)**, in response to "the drawer is missing
your findings, like this:" (user pasted a real CLI report for a genuine
phishing email, `ClaireMorgan.eml` — a copyright-takedown lure from
`george.kidunda25@mustudent.ac.tz`, SUSPICIOUS 53.5, caught an `ai:` custom
tag no regex bank covers):
- Made it a complete standalone `<!DOCTYPE html>` document (was a bare
  fragment relying on the Artifact tool's auto-wrapping) so it runs
  correctly outside the Artifact viewer, moved out of the session scratchpad
  into the repo proper.
- Ported the real scoring engine into the dashboard's JS, not just the
  presentation: exact `weights.yaml` stage weights, the exact max-plus blend
  from `verdict.py`, the exact thresholds, and `report.py`'s
  `_FLAG_DESCRIPTIONS`/`_FLAG_PREFIX_DESCRIPTIONS` verbatim. Verified in Node
  (not eyeballed) that several synthetic scenarios reproduce **actual cases
  from this session exactly** — Claire Morgan lands at precisely 53.5, the
  wooga ShareFile/OAuth case at precisely 100.0. Added hard-override
  scenarios (bec_vip_impersonation/sender_lookalike_domain/
  banned_attachment_type/threat_intel_hit) at their real fixed scores.
  Synthetic email generation is now a bank of full 6-stage templates, not a
  flat random score.
- Detail drawer now shows the full stage-by-stage breakdown, AI assessment,
  translated "why this verdict" list, verdict-margin line, hard-override
  banner, and the complete categorized IOC breakdown with context
  annotations — matching the CLI report's structure, not an abbreviated
  summary of it. Added a "Copy as text report" button that reproduces the
  exact `text_report()` plain-text format for pasting into a ticket/Wazuh
  note.
- User's plan: iterate on this locally for a while, decide the real hosting
  environment later alongside `pdax-email-core` itself — deliberately not
  decided yet, don't assume one.

**LLM-call volume control (`app/pipeline/runner.py`, new
`PDAX_LLM_TRIAGE`)**: user's concern — Google AI Studio (and any per-call
AI provider) can't sustain analyzing every single production email; asked
me to think through alternatives. Presented four options (triage first /
Vertex AI / Bedrock Provisioned Throughput / self-hosted open-weight model)
as a real tradeoff table rather than picking one — **user chose triage
first**, since it needs no vendor decision and directly attacks the actual
problem (most mail doesn't need an LLM call to resolve).

Implemented as a two-pass cascade in `run_pipeline()`:
1. Free `HeuristicProvider` content pass always runs first (cheap,
   unlimited, already sufficient for every hard override — the regex BEC
   bank covers `bec_pattern` for the VIP+BEC combo the same as the paid
   providers' prompt does).
2. `_should_escalate()`: skip the real LLM call if a hard override already
   fired, or if the heuristic-only composite score isn't within
   `PDAX_LLM_TRIAGE_MARGIN` (default 15) points of the LOW/MALICIOUS
   thresholds — i.e. comfortably clean or comfortably malicious cases never
   spend a call. Otherwise, call the real requested provider
   (`BedrockProvider`/`GeminiProvider`) and let its result replace the
   heuristic one.
- **Off by default** (`PDAX_LLM_TRIAGE=1` to enable), specifically so
  `analyze.py`'s interactive debugging workflow (force a specific provider
  on one email, see what it says) never silently skips a call the user
  explicitly asked for — this is meant for production/gateway volume only.
- The decision is always auditable: `content_ai`'s `facts` carry
  `triage_skipped_llm` / `triage_escalated`, surfaced in both
  `text_report()` (a `triage:` line under the stage) and `audit_record()`'s
  JSON.
- 5 new tests in `tests/test_llm_triage.py` (mocked client — no real API
  calls): default-off behavior unchanged, hard-override case skips, clean
  case skips, a constructed ambiguous case (heuristic score near the LOW
  boundary) correctly escalates and the final stage reflects the real
  provider's output, env-var-only activation works without the kwarg.
- **The margin default (15) is not calibrated against real traffic** —
  explicitly documented in README as needing tuning once real production
  volume/golden-set data exists. Don't treat 15 as validated.
- **Not implemented, mentioned but out of scope for this ask**: response
  caching for near-identical bulk-campaign emails (a second volume-reduction
  lever raised alongside triage) and the three infra alternatives
  (Vertex AI / Bedrock Provisioned Throughput / self-hosted model) — all
  still open options if triage alone isn't enough headroom.

## What changed 2026-08-04 — third content provider: GLM via Vertex AI Model Garden

Follow-on from the previous day's volume conversation: user has already
decided to move off AI Studio specifically for its rate limits, and has an
"Access Key" for GLM (Zhipu AI/Z.ai) on Google Cloud's Vertex AI Model
Garden. Grounded this in a live web search before building anything (same
discipline as the earlier Gemini model-naming fiasco) rather than guessing:

- **GLM on Vertex AI is a MaaS (Model-as-a-Service) integration** — fully
  managed, no self-deploy — called via an **OpenAI-compatible Chat
  Completions endpoint**:
  `https://aiplatform.googleapis.com/v1/projects/{PROJECT}/locations/global/endpoints/openapi/chat/completions`,
  model id like `zai-org/glm-4.7-maas` (GLM-5/5.1 also exist as of this
  writing — verify what's actually enabled in the user's Model Garden
  console rather than trusting a hardcoded default, same lesson as Gemini).
- **Two flags surfaced and given to the user directly, not silently
  assumed away** (per CLAUDE.md's "any provider sending content off-box is
  a privacy-boundary decision" rule):
  1. The documented path is `locations/global`, not a pinned region —
     possibly meaning the region-pinning benefit that motivated considering
     Vertex AI over AI Studio doesn't actually apply to GLM specifically.
     Unconfirmed either way; needs checking in the GCP console.
  2. GLM is developed by Zhipu AI (Z.ai, Chinese lab), not Google — a
     different data-governance question than Google's own first-party
     Gemini, even though the call is served through Google's
     infrastructure. Needs its own explicit sign-off, not inherited from
     the Gemini conversation.
- **Credential format is unconfirmed** — the user called it an "Access
  Key," not clearly a stable API key vs. a short-lived (~1hr) GCP OAuth2
  token copied from a console workflow. Built `GLMProvider` to accept
  either via a plain string for now (env var `PDAX_GLM_API_KEY`); flagged in
  the docstring/README that if it turns out to be short-lived, a
  long-running gateway will need real token refresh (a service account via
  `google-auth`, passed as a callable — `openai.OpenAI(api_key=...)`
  confirmed via `inspect.signature` to accept `str | Callable[[], str]`,
  not just a fixed string) instead of the current fixed-string approach.
  Don't build the refresh logic preemptively; wait until this is confirmed
  to actually be the failure mode.
- **Implementation**: `GLMProvider` in `content_ai.py`, using the `openai`
  Python package (verified its actual client/response interface via
  `inspect` rather than assumed — `OpenAI(api_key=, base_url=)`,
  `client.chat.completions.create(...)`,
  `response.choices[0].message.content`) pointed at the Vertex MaaS base
  URL. Shares `_SYSTEM_PROMPT`/`_ContentAnalysis` with Bedrock/Gemini.
  Structured output via `response_format={"type":"json_object"}` (the
  OpenAI-compatible baseline — whether the stronger `json_schema` mode is
  honored through this specific gateway is unconfirmed) plus an explicit
  schema instruction in the user message as backstop. Same
  retry-once/honest-degrade contract as the other two providers.
- **Fixed the shared `_SYSTEM_PROMPT` while here**: it said "emit ONE tool
  call with your conclusion," which is Bedrock-specific phrasing that
  doesn't fit Gemini's `response_schema` mechanism or GLM's plain-JSON
  approach. Reworded to "respond with your conclusion in the exact
  structured format required of you" — provider-neutral, benefits all
  three, not just GLM.
- Selected via `PDAX_CONTENT_PROVIDER=glm`; included in the
  `PDAX_LLM_TRIAGE` cascade's `is_llm_provider` check alongside Bedrock/
  Gemini, so the volume-control work from the previous entry applies to
  GLM too without extra wiring.
- 7 new tests in `tests/test_content_ai_glm.py` (mocked `openai` client, no
  real Vertex/GLM calls): happy path, repair-retry recovery,
  persistent-schema-failure degradation, empty-response degradation,
  malformed-JSON degradation, missing-project-id degrades without crashing,
  env-var selector. Full suite is now 28 tests, still precision/recall
  1.00/1.00, no regressions.
- **Nothing has been run against the real Vertex/GLM endpoint yet** — no
  credentials were available in this environment. First real run should
  confirm the credential-format question above before anything else.

## What changed 2026-08-04 (later same day) — GLM credentials resolved + first real Model Garden call

User dropped a real GCP service-account key at repo root (`credentials.json`,
project `totemic-chalice-496105-i5`) and asked to wire it into the Model
Garden integration — this directly resolves the "credential format
unconfirmed" flag from the entry above.

- **`_ServiceAccountTokenProvider`** (new class in `content_ai.py`): wraps
  `google.oauth2.service_account.Credentials` + `google.auth.transport
  .requests.Request`, exposed as a zero-arg callable. Passed as `GLMProvider`'s
  `api_key=` to `openai.OpenAI(...)` — re-verified via reading
  `openai==2.53.0`'s actual source (`_client.py`) that a callable is stored
  as `_api_key_provider` and re-invoked on **every request** via
  `_prepare_options`/`_refresh_api_key`, not just once at construction (an
  earlier quick check misread this — confirmed properly the second time by
  tracing the real call path, not by printing `.api_key` right after
  `__init__`). So a long-running gateway process keeps working past the
  token's ~1hr expiry without restarting. `Credentials.valid` avoids
  re-authenticating with Google on every single email.
- **`GLMProvider` changes**: new `credentials_path` param / env
  (`PDAX_GLM_CREDENTIALS_PATH`, falls back to the standard
  `GOOGLE_APPLICATION_CREDENTIALS`); `project_id` now auto-derived from the
  credentials file's own `project_id` field when `PDAX_GLM_PROJECT_ID` isn't
  set, so one file is enough instead of two separate settings that have to
  agree. `_resolve_api_key()` centralizes the precedence: explicit
  `PDAX_GLM_API_KEY` string wins if set, else a cached
  `_ServiceAccountTokenProvider` built from `credentials_path`, else `None`
  (degrades honestly downstream, same contract as every other failure mode).
- **12 new tests** in `tests/test_content_ai_glm.py` (credential resolution
  precedence, project-id derivation incl. explicit-wins-over-file and
  missing-file handling, token-provider caching, mint-and-cache-until-expired
  behavior) — all still mocked/offline, no real Vertex calls in the suite
  itself. Full suite now 41 tests, still precision/recall 1.00/1.00.
- **First real call made against the live endpoint** (not just mocked tests)
  using the user's actual credentials — auth and endpoint wiring worked
  correctly on the first successful round trip (project id auto-derived
  correctly, token minted, real GLM response came back). Run via one-off
  inline `python3 -c` commands, nothing saved to the repo; no test file
  hits the real endpoint.
- **Found and fixed a real bug this surfaced**: `zai-org/glm-4.7-maas` is a
  reasoning model — the real response carried a `message.reasoning_content`
  field (hidden chain-of-thought, ~5,800 chars / most of the completion
  tokens) ahead of the actual `message.content` JSON answer. The previous
  700-token default degraded silently on essentially every real call
  (`finish_reason="length"`, empty `content`, but pipeline stayed up per the
  honest-degrade contract — never crashed or lied about the result, so this
  was masked until an actual live call was made). Raised the default
  `max_tokens` to 4000; verified live afterward with **default settings, no
  manual overrides** that a real phishing-styled test email now scores
  correctly (85.0, non-degraded) instead of degrading to 0. `_extract_text()`
  intentionally still ignores `reasoning_content` — it's scratch work, not a
  structured answer, and folding it in would break the pydantic parse.
- **`credentials.json` is a live secret** — this project isn't a git repo
  yet (confirmed via `git rev-parse`), so there was no accidental-commit
  risk today, but added a `.gitignore` (`credentials.json`, `*.pem`, `.env`,
  `.venv/`) as a defensive default for whenever `git init` does happen.
  Don't assume this file is safe to reference by path in any future
  shared/committed script — treat it the same as any other production
  secret.
- README's GLM section rewritten to match: `PDAX_GLM_CREDENTIALS_PATH`
  as the documented setup path (not the old ambiguous "Access Key" framing),
  the token-refresh mechanism explained, and the 4000-token reasoning-model
  note. `requirements.txt` now lists `google-auth` as the additional optional
  dep for this path (already present in the dev `.venv` as a transitive dep
  of `google-genai`, but not previously declared for GLM's own sake).
- **Still open / not done here**: the region-pinning and GLM
  provenance/data-governance sign-offs from the previous entry are
  unchanged — getting the credential and token-budget issues working is not
  the same as clearing those two flags. Don't treat this entry as closing
  them.

## What changed 2026-08-04 (later still) — eml_analysis_agent.py: standalone batch report tool

User has a separate spec, `eml_analysis_agent.md` (not authored this
session — a fuller forensic/analyst schema: metadata, header authentication,
content/NLP, threat assessment with suspicious-URL and attachment tables),
and asked for a script that runs it over `samples/*.eml` via the Model
Garden connection just wired up, writing `samples_output/<stem>.md` per
email.

- **New top-level script `eml_analysis_agent.py`**, deliberately *not* part
  of `content_ai.py`/`ContentProvider` or the scored pipeline — it produces
  a full narrative report, not a `(score, findings, facts)` contribution,
  and never touches `verdict.py`. Reuses `GLMProvider(credentials_path=...)
  ._get_client()` to get an already-authenticated OpenAI-compatible client
  (project-id auto-detected, token-refresh wiring) rather than duplicating
  any GCP auth code.
- **Same prompt-injection posture as the scored pipeline**: the spec's own
  Section 5 system prompt had no injection-defense clause, so one was added
  (same pattern as `content_ai.py`'s shared `_SYSTEM_PROMPT`) — several
  bundled samples are real phishing/BEC content, so this isn't
  hypothetical.
- **Ground-truth vs. model judgment split**, matching the codebase's
  existing "AI never owns the facts" instinct even though this tool sits
  outside `verdict.py`: metadata, attachment filenames/sizes/SHA-256
  hashes, and extracted URLs are computed deterministically in Python
  (stdlib `email`/`hashlib`/regex, close to the reference implementation in
  the spec) and handed to the model as facts not to be reinvented; the
  model only adds risk judgment (`is_flagged`/`reason`/`mismatch`) on top.
- **`max_tokens=6000` default** — same reasoning-model lesson as the
  GLMProvider fix above, confirmed live again here since this schema's JSON
  answer is larger than the phishing-only one.
- **Ran the full batch live** (13 files, real Vertex AI calls, ~15-80s
  each): 13/13 succeeded. One real inconsistency surfaced in the raw run:
  `phish_lookalike.eml` came back `"risk_level": "CRITICAL"` paired with
  `"risk_score": 9` — internally contradictory against the schema's own
  0=benign/100=unambiguous scale (a same-file re-run scored 95, so this
  was a one-off model glitch, not a prompt/schema bug — `temperature=0`
  doesn't fully guarantee determinism through this MaaS gateway). Rather
  than silently trust or silently "fix" a disagreeing field, added
  `_consistency_warning()`: flags the report itself and the console summary
  line (`[INCONSISTENT — see report]`) whenever `risk_level` and
  `risk_score` fall outside each other's expected range, so an analyst
  reading `samples_output/` notices instead of trusting a wrong-looking
  number. Re-ran that one file after adding the check; came back
  CRITICAL/95, no warning fired. All 13 reports in `samples_output/` are
  now internally consistent.
- Not covered: no test file for this script (it's a thin batch-orchestration
  layer over already-tested `GLMProvider`, and its own correctness is
  "did it call the endpoint and write readable Markdown," verified live
  rather than mocked) — if it grows real branching logic later, add one.
