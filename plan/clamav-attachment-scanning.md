# ClamAV attachment scanning — implementation plan

Status: **plan only** (no code in this change).
Owner: SEGS pipeline / static worker.
Related: TMES `virtual_analyzer` policy category.

---

## 1. Why this exists

SEGS already inspects attachments with **static forensics** (magic bytes, macros, archives, PDF active content) and optional **VirusTotal hash reputation**. Neither catches known malware that looks like a normal Office/PDF/ZIP until a signature or community hash exists.

ClamAV fills that gap as a **local, in-house signature engine**:

- No attachment bytes leave PDAX infrastructure (RA 10173 / data-residency — same reason public detonators were rejected).
- Complements, does not replace, static forensics or VT.
- Known families (EICAR, ransomware, commodity loaders, phishing kits) become a deterministic `MALICIOUS` verdict instead of waiting on VT quota or an LLM.

ClamAV is **not** a detonation sandbox. It does not execute files. A future CAPEv2/Cuckoo provider can still occupy the same `SandboxProvider` interface.

---

## 2. Current state (already in the tree)

The detection *contract* is largely written. The daemon, dependency, and deploy path are not.

| Piece | Location | State |
|-------|----------|--------|
| `ClamAVSandboxProvider` | `workers/pipeline/sandbox.py` | Streams attachment bytes to `clamd` via `pyclamd.scan_stream`. Never writes files to disk. Caps at 20 MB. Degrades on ImportError / unreachable daemon. |
| Factory | `get_default_sandbox_provider()` | `SEG_SANDBOX_PROVIDER=clamav` → ClamAV; anything else → `NullSandboxProvider`. |
| Attachment wiring | `workers/pipeline/attachments.py` | Calls `detonate()` per attachment **only if** `virtual_analyzer` is enabled. Stores facts on `rec["sandbox"]`. Flags `sandbox_clam_found` / `sandbox_clam_unavailable`. |
| Hard override | `workers/pipeline/verdict.py` | `sandbox_clam_found` + `virtual_analyzer` on → `clam_malicious`, verdict MALICIOUS, score 100. |
| Policy category | `workers/pipeline/policy.py` | Prefix `sandbox*` → `virtual_analyzer`. Code default-off; `rules/detection/policy.yaml` has `enabled: true`. |
| Report / LLM | `backend/report.py`, `workers/pipeline/content_ai.py` | Attachment table ClamAV column; LLM prompt includes ClamAV hits. |
| URL string scan | `workers/pipeline/intel.py` `_clam_url_scan()` | Same env switch. Local signature lookup only (no HTTP to the URL). Hit → `intel_url_clam:` → `threat_intel_hit`. |
| Settings | `backend/config.py` | `sandbox_provider`, `clamd_socket`, `clamd_host`, `clamd_port`. |
| Docs / env | `docs/configuration.md`, `.env.example` | Activation checklist exists; it assumes a daemon that is not deployed. |
| `pyclamd` | `requirements.txt`, `pyproject.toml` | **Commented out / not declared.** Provider always takes the ImportError path today. |
| Compose / Docker / Terraform | `docker-compose.yml`, `deploy/docker/*`, `infra/` | **No clamd service, sidecar, or secret keys.** |
| Tests | `backend/tests/pipeline/test_sandbox.py` | Only `NullSandboxProvider` + call-gating. No ClamAV unit tests, no EICAR fixture. |

**Double scan (bug to fix during this work):** `attachments.py` already calls `detonate()`. `workers/static.py` then calls `provider.detonate()` again for every attachment and records a separate `sandbox` stage. That doubles clamd load and can desync facts if the two results differ. Verdict currently keys off the **attachments** stage, not the extra sandbox stage.

---

## 3. Goal

Make ClamAV a **default-available, opt-in-at-runtime** attachment AV layer:

1. Every attachment that static forensics already sees is also stream-scanned by a reachable `clamd`.
2. A signature hit is a hard-override `MALICIOUS` (`clam_malicious`), same confidence class as a VT FOUND hit.
3. If ClamAV is off, missing, or unreachable, the rest of the pipeline is unchanged (static forensics + VT + LLM still run).
4. Local `docker compose` can run an EICAR `.eml` and see the hit without installing ClamAV on the host.
5. Production Fargate can reach a shared `clamd` without putting the CVD database inside every API/worker image.

---

## 4. Non-goals

- Do **not** send attachment bytes to VirusTotal, Hybrid Analysis, Any.run, or any public detonator.
- Do **not** write attachment payloads to disk for `clamscan` CLI (stream to `clamd` only).
- Do **not** treat ClamAV as TMES Virtual Analyzer / sandbox detonation. Keep the `SandboxProvider` interface so a real detonator can be added later as a second provider (`cape`, `cuckoo`), not by replacing ClamAV.
- Do **not** enable `SEG_LANDING_FETCH`. URL ClamAV stays a **string** scan.
- Do **not** bake `clamd` into the API/worker Python images. Sidecar or dedicated service only.
- Do **not** scan the entire `.eml` as one blob. Scan decoded attachment payloads (and, optionally, archive members already extracted by forensics).

---

## 5. How it sits in the pipeline

Existing order (unchanged):

```
headers → sender → urls → deception → attachments → intel → content_ai
                                              ↑
                              static forensics, then ClamAV
```

Layering for attachments (already documented in `docs/configuration.md`):

| Layer | What it catches | When it runs |
|-------|-----------------|--------------|
| 1. Static forensics | Type spoof, macros, zip-bombs, PDF JS | Always |
| 2. ClamAV | Known malware signatures | `SEG_SANDBOX_PROVIDER=clamav` **and** `virtual_analyzer` enabled |
| 3. VT hash | Community-known file hashes | Intel client + API key |
| 4. LLM | Novel lure / macro intent | Opt-in LLM provider |

Call-time gating stays: `virtual_analyzer` off → `detonate()` is **not** called (unlike other categories that compute then suppress). That is correct for an action that costs latency and daemon load.

Intel URL ClamAV stays on the **same env switch** (`SEG_SANDBOX_PROVIDER=clamav`) but a **different policy gate** (`correlated_intelligence`). Do not merge those gates.

Callers that must reach `clamd`:

- **Static worker** — live Gmail copies (`workers/static.py` → `attachments.run`).
- **API analyze** — Analyst upload via `runner.run_pipeline()` (`backend/api/routers/analyze.py`).
- **CLI / eval** — `cli/analyze.py` / eval harness, same runner.

Content-AI, thread-AI, campaign, and sender workers do **not** need `clamd` if they consume stored attachment facts.

---

## 6. Target architecture

### 6.1 Client (SEGS)

Keep `ClamAVSandboxProvider` as the only in-process client.

Tighten it while implementing:

- **One shared client** used by both `sandbox.py` and `intel.py` (today connection setup is duplicated). Put `clamd` connect/ping/scan in one module, e.g. `workers/pipeline/clamd_client.py`, and have both call it.
- **Reuse the connection** across attachments in one email (and across emails in the worker process). `pyclamd` currently constructs a new socket per `detonate()`.
- **Timeouts.** `scan_stream` can block. Bound it (suggest 8–10 s per attachment, fail → `unavailable`, not hang the 300 s scan lease).
- **Ping at first use.** If `ping()` fails, skip remaining attachments on that email and set one `sandbox_clam_unavailable` rather than N identical flags.
- Keep in-memory `scan_stream`. Never `INSTREAM` from a temp file.

Suggested `detonate()` outcomes (already close; lock the contract):

| clamd result | score | findings | facts.result | Verdict effect |
|--------------|-------|----------|--------------|----------------|
| None (clean) | 0 | [] | `clean` | none |
| FOUND | 85 | `clam_found` | `malicious` + signature | `clam_malicious` override |
| empty / >20 MB | 0 | [] | `skipped` | none |
| pyclamd missing | 0 | `clam_unavailable` | `pyclamd_not_installed` | degraded, not MALICIOUS |
| timeout / error | 0 | `clam_unavailable` | `unavailable` | degraded, not MALICIOUS |

Do **not** hard-override on `clam_unavailable`. Static forensics remains the verdict.

### 6.2 Daemon (local)

Add a Compose service. Recommended image: `clamav/clamav:stable` (official, includes `clamd` + `freshclam`).

```
services:
  clamav:
    image: clamav/clamav:stable
    ports: ["3310:3310"]          # optional; workers can use the compose network
    volumes:
      - clamav-db:/var/lib/clamav
    healthcheck:
      test: ["CMD", "clamdscan", "--ping", "1"]   # or clamd ping as documented for the image
      interval: 30s
      timeout: 10s
      retries: 10
      start_period: 120s          # first CVD pull is slow
```

Wire **api** and **static** (and any process that runs `run_pipeline`):

```
SEG_SANDBOX_PROVIDER=clamav
SEG_CLAMD_HOST=clamav
SEG_CLAMD_PORT=3310
```

Leave `SEG_CLAMD_SOCKET` empty in Compose (TCP across containers). Unix sockets are for a future same-task sidecar if we share a volume.

`depends_on: clamav: condition: service_healthy` for `static` and `api` so the first EICAR test is not a race against CVD download.

### 6.3 Daemon (production Fargate)

Do **not** put ClamAV inside every worker replica. CVD is hundreds of MB; `freshclam` needs outbound HTTPS; memory is typically 1–2 GB.

Preferred: **one internal ECS service** `segs-clamav`:

- Task: official ClamAV image (or a thin wrapper if the stock image needs a custom `clamd.conf`).
- CPU/memory: start at 1024 CPU / 2048 MB; tune after first CVD load.
- Service discovery: Cloud Map or an internal NLB on TCP 3310, SG only from API + static tasks.
- `freshclam` on a schedule inside the container (image default is fine). Persist `/var/lib/clamav` on EFS so new tasks do not re-download the full DB on every replace.
- Secrets / env (non-secret): `SEG_SANDBOX_PROVIDER=clamav`, `SEG_CLAMD_HOST=<cloudmap>`, `SEG_CLAMD_PORT=3310`.
- Add those keys to `infra/locals.tf` `app_secret_keys` (or `shared_environment` if they are not secret). Host/port are not secrets; the provider switch can live in Secrets Manager next to `SEG_INTEL_CLIENT`.

Fallback if ops want zero extra service: ClamAV sidecar on the **static** task only. Then Analyst **API analyze** uploads would not scan unless the API task also has a sidecar or talks to the static sidecar (awkward). Shared service is cleaner because analyze and static both need it.

### 6.4 clamd.conf knobs to set explicitly

| Setting | Suggested | Why |
|---------|-----------|-----|
| `TCPSocket 3310` / `TCPAddr` | bind to the task IP, not only 127.0.0.1 | Compose/ECS clients are other containers |
| `StreamMaxLength` | ≥ 25 MB | Must exceed provider `MAX_SCAN_BYTES` (20 MB) or clamd rejects streams |
| `MaxScanSize` / `MaxFileSize` | ≥ 25 MB | Same |
| `MaxScanTime` | ~8–10 s | Align with client timeout |
| `DetectPUA` | off initially | PUAs inflate FPs on macros/installers; enable later if SOC wants it |
| `OLE2BlockMacros` | off | We already flag macros in forensics; ClamAV should fire on *malware*, not “has VBA” |
| `ScanArchive` | on | Nested zip/docx members |
| `MaxRecursion` / `MaxFiles` | match forensics caps (depth ~5, files ~3000) | Zip-bomb defense |

---

## 7. Implementation phases

### Phase 0 — Contract cleanup (no daemon yet)

1. Extract `clamd_client.py` (connect, ping, `scan_bytes`, `scan_url_string`).
2. Point `ClamAVSandboxProvider` and `_clam_url_scan` at it.
3. Remove the second `detonate()` loop in `workers/static.py`. Either:
   - drop the extra `sandbox` stage, or
   - build it from `attachments.facts["attachments"][*]["sandbox"]` so facts stay in one place.
4. Rewrite the `sandbox.py` module docstring: ClamAV is a real signature provider; detonation remains unimplemented.
5. Align policy defaults: `policy.yaml` already enables `virtual_analyzer`. Update `policy.py` `_DEFAULT_ENABLED["virtual_analyzer"]` to `True` **or** keep default-off and document that yaml wins in production. Prefer yaml-as-source-of-truth and fix `test_e2e_virtual_analyzer_toggle_has_no_observable_effect_yet` (it is already a lie once a provider can score).
6. Uncomment `pyclamd` in `requirements.txt` and add it to `pyproject.toml` dependencies (optional extra `clamav` is acceptable if we want CI without the daemon; then Docker images must install the extra).

### Phase 1 — Local daemon + unit tests

1. Compose `clamav` service + volume + healthcheck.
2. Document in `.env.example`: for compose, set host to `clamav`; for host-run pytest against compose, `localhost:3310`.
3. Tests that **do not** need a daemon:
   - Fake/`RecordingProvider` already exists.
   - Mock `pyclamd` to return `None`, `{stream: (FOUND, Eicar-Test-Signature)}`, and raise.
   - Verdict: fixture attachment with `sandbox_clam_found` → `clam_malicious`.
   - Unavailable: no score, no override, flag visible.
   - Size skip: payload > 20 MB.
   - `virtual_analyzer` disabled: provider not called even if env is `clamav`.
4. Tests that **do** need a daemon (mark `pytest.mark.integration`, skip if `clamd` ping fails):
   - EICAR COM bytes in an `.eml` attachment → `sandbox_clam_found` + `clam_malicious`.
   - Clean `hello.txt` → `clean`, no override.
   - Do not commit live malware. EICAR is the standard harmless test string.

### Phase 2 — Production deploy

1. Terraform: ECS service + SG + service discovery + EFS for CVD (if we persist DB).
2. Secrets: `SEG_SANDBOX_PROVIDER`, `SEG_CLAMD_HOST`, `SEG_CLAMD_PORT`.
3. CloudWatch: `clamd` unhealthy, CVD age (freshclam logs), scan latency, FOUND count, unavailable rate.
4. Alert if `sandbox_clam_unavailable` appears on a high fraction of attachment emails (daemon down, not “no malware”).

### Phase 3 — Hardening (after EICAR works in prod)

- Scan **archive members** already listed by `attachment_forensics` when the outer file is clean but a nested `.exe`/`.js` exists. ClamAV `ScanArchive` may already cover this; verify with a zip-of-EICAR fixture before adding a second pass.
- Optional: skip scanning of obvious non-executables (tiny inline images) to save CPU — only after measuring. Default is scan everything; static forensics already paid the decode cost.
- Connection pool / circuit breaker if static workers stampede a single clamd.
- Horizontal scale: second clamav task behind the NLB if p99 scan time grows.

---

## 8. Scoring and policy (lock these rules)

- `sandbox_clam_found` is **authoritative**. It bypasses weighted scoring. Same class as `threat_intel_hit`.
- `sandbox_clam_unavailable` is **advisory**. It must not floor a CLEAN email to SUSPICIOUS.
- Provider sub-score 85 is only used if the override is later disabled in policy; the override is the production path.
- Allowlist/blocklist still apply after verdict (`runner._apply_list_overrides()`). A ClamAV hit should **not** be allowlisted away without an explicit SOC decision — call that out in ops docs, do not special-case in code unless product asks.
- `virtual_analyzer: enabled: false` remains the kill switch for attachment ClamAV scoring **without** tearing down the daemon. URL ClamAV is independent (`correlated_intelligence`).

---

## 9. Files to touch when implementing

| Area | Files |
|------|--------|
| Client | `workers/pipeline/sandbox.py`, new `workers/pipeline/clamd_client.py`, `workers/pipeline/intel.py` |
| Wiring | `workers/pipeline/attachments.py`, `workers/static.py` |
| Verdict / policy | `workers/pipeline/verdict.py` (no logic change expected), `workers/pipeline/policy.py`, `rules/detection/policy.yaml` |
| Config | `backend/config.py`, `.env.example`, `requirements.txt`, `pyproject.toml` |
| Local run | `docker-compose.yml` |
| Prod | `infra/workers.tf` or new `infra/clamav.tf`, `infra/locals.tf`, security groups |
| Tests | `backend/tests/pipeline/test_sandbox.py`, new `test_clamav.py`, optional `samples/fixtures/eicar.eml` |
| Docs | `docs/configuration.md`, `docs/operations.md`, `docs/architecture.md` (sandbox paragraph), `instructions.md` |
| Health | optional `/api/health` or static worker health: `clamd ping` when provider is clamav — degraded, not 5xx |

---

## 10. Privacy, safety, ops constraints

- Bytes stay on the SEGS network. `clamd` is a scanner, not an executor. Still treat payloads as hostile: stream size caps, timeouts, no disk spool of decoded attachments.
- `freshclam` needs **egress to clamav.net (or a mirror)**. That is signature metadata, not mail. Document the SG exception. Pinning a private CVD mirror is a later ops improvement.
- Do not log full signatures + filenames + mailbox in the same line if that creates a PII+IOC mash; signature name + sha256 is enough.
- EICAR in production smoke tests: fine. Do not ship other malware samples in git.

---

## 11. Risks

| Risk | Mitigation |
|------|---------|
| First `freshclam` takes minutes; compose tests fail | Healthcheck + `start_period`; integration tests skip until ping |
| Fargate OOM on CVD | Dedicated task 2 GB; not a sidecar on 512 MB workers |
| False positives on macros / PUAs | `DetectPUA` off; rely on forensics for “has macro” |
| clamd down → silent miss | `sandbox_clam_unavailable` in report; alert on rate; do not fail closed (mail still analyzed) |
| Double `detonate()` doubles latency | Remove static.py second loop in Phase 0 |
| `StreamMaxLength` < 20 MB | Set clamd.conf above client cap |
| Analysts confuse ClamAV with “sandbox detonated” | UI/report copy: “AV signature”, not “detonated” |
| Shared clamd becomes a bottleneck | Timeout + skip; later NLB + 2 tasks |

---

## 12. Open decisions (resolve before Phase 2)

1. **Shared ECS service vs sidecar on static (+ api)?** Recommendation: shared service.
2. **Default `SEG_SANDBOX_PROVIDER` in prod:** `clamav` once the service is healthy, `null` until then. Do not flip the default in code before the daemon exists.
3. **Optional extra vs hard `pyclamd` dependency.** Recommendation: hard dependency in the Docker images (small library); unit tests mock it so CI does not need clamd.
4. **Scan inline CID images?** Default yes (cheap). Revisit if p99 latency is dominated by logos.

---

## 13. Acceptance criteria

Local:

- [ ] `docker compose up` starts `clamav` healthy and `static`/`api` can TCP 3310.
- [ ] Upload/analyze an EICAR attachment `.eml` → Attachment Detail shows `MALICIOUS — Eicar-*`, hard override `clam_malicious`, verdict MALICIOUS.
- [ ] Clean text attachment → ClamAV `clean`, no override.
- [ ] Stop the clamav container → `sandbox_clam_unavailable`, pipeline still returns a verdict from other stages.
- [ ] `virtual_analyzer` disabled → no clamd calls, no `clam_malicious`.
- [ ] Pytest unit suite passes without a daemon. Integration test skips or passes when daemon is up.
- [ ] `workers/static.py` scans each attachment **once**.

Production (Phase 2):

- [ ] Static worker and API analyze both reach clamd.
- [ ] CVD updates without rebuilding app images.
- [ ] CloudWatch shows ping health and FOUND / unavailable counts.
- [ ] No attachment bytes in CloudWatch logs.

---

## 14. Suggested first implementation slice

Smallest useful PR after this plan:

1. Phase 0 contract cleanup + mock tests + `pyclamd` dependency.
2. Compose `clamav` service + `.env.example` uncommented for local.
3. One integration test: EICAR.

Leave Terraform for a follow-up once local EICAR is green.
