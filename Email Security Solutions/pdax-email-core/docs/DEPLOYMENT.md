# SEGS Deployment Guide

**Standing SEGS up in your environment — from evaluation to inline enforcement.**

Last updated: 2026-08-25

This guide is honest about what's ready today versus what needs integration
work. Read **Phase 0** first — it decides which of the later phases apply to you.

---

## Phase 0 — Decide your deployment model

SEGS has one detection brain (`run_pipeline()`) and three ways to feed mail into
it. Pick based on your mail infrastructure and how aggressive you want to be:

| Model | How mail reaches SEGS | Maturity | Best for |
|---|---|---|---|
| **A. Evaluation / shadow** | You drop `.eml` files (or a spool export) into a folder; the hold consumer scans them | ✅ **Ready now** | Proving detection quality against your real mail, risk-free |
| **B. Inline SMTP hold** | Your MTA (Postfix/Rspamd) holds inbound mail and hands it to SEGS *before* delivery | ⚠️ **Adapter needs building** (spool-based today) | Blocking threats before they land — strongest posture |
| **C. Post-delivery API** | SEGS pulls delivered mail via Gmail/Graph API and quarantines retroactively | ⚠️ **Receiver needs building** | Google Workspace / M365 with no MTA change |

**Recommended path:** stand up **Model A first** (Phases 1–6, plus 7A) — it gives
you a real, running system and lets you tune detection on your own traffic in
shadow mode with zero delivery risk. Graduate to **B or C** (Phase 7) only once
shadow-mode false-positives are near zero.

**Two decisions to make now:**
1. Which mail platform are you protecting? (Postfix/Exchange on-prem → Model B; Google Workspace / Microsoft 365 → Model C)
2. Inline (block before inbox) or post-delivery (quarantine just after)?

---

## Phase 1 — Provision the host

A single modest Linux VM is enough to start (2 vCPU / 4 GB RAM).

```bash
# Debian/Ubuntu example
sudo apt update && sudo apt install -y python3 python3-venv python3-pip git
python3 --version        # must be 3.9+ (3.12+ recommended)

# Dedicated service account (never run as root)
sudo useradd -r -m -d /opt/segs -s /usr/sbin/nologin segs
```

Network posture: SEGS binds to **localhost only**; a reverse proxy terminates
TLS in front (Phase 5). No inbound ports are exposed directly.

---

## Phase 2 — Install SEGS

```bash
sudo -u segs -H bash
cd /opt/segs
git clone https://github.com/ronchaic/segs-secure-email-gateway.git app
cd app
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 -m pytest tests/ -q        # sanity check — expect all green
```

---

## Phase 3 — Configure (`.env`)

Create `/opt/segs/app/.env` (chmod `600` — it holds secrets). Everything is
optional; SEGS runs fully offline with none of it. Turn things on deliberately.

```bash
# ---- Enforcement (start safe) ----
SEG_ENFORCE=shadow                 # shadow | quarantine | reject  (keep shadow at first)

# ---- Web console (production) ----
SEG_COOKIE_SECURE=1                # REQUIRED once you're behind HTTPS (Phase 5)

# ---- AI content analysis (optional; pick ONE provider) ----
# SEG_CONTENT_PROVIDER=ollama      # RECOMMENDED for production — self-hosted, no data leaves your infra, no per-call cost
# SEG_OLLAMA_MODEL_ID=llama3       # a model you've `ollama pull`-ed
# SEG_LLM_TRIAGE=1                 # only spend an LLM call on ambiguous mail (production volume control)

# ---- Threat intel (optional) ----
# SEG_INTEL_CLIENT=vt_abuseipdb
# SEG_VT_API_KEY=...
# SEG_ABUSEIPDB_API_KEY=...

# ---- Enrichment (optional) ----
# SEG_CORRELATION_STORE=1          # behavioral campaign correlation (recommended for a real gateway)
# SEG_RDAP_LOOKUP=1                # newly-registered-domain checks

# ---- Deep EML analyzer (optional; needs GCP creds) ----
# SEG_GLM_CREDENTIALS_PATH=/opt/segs/app/credentials.json
```

> **Data-residency note (important for regulated environments):** the cloud AI
> providers (Gemini, GLM) send email content off your infrastructure and carry
> RA 10173 / DPO sign-off caveats documented in `README.md`. **Self-hosted
> Ollama is the recommended production default** precisely because nothing
> leaves your network. Choose the provider as a governance decision, not just a
> technical one.

---

## Phase 4 — First run & create the admin

```bash
cd /opt/segs/app && source .venv/bin/activate
uvicorn server.main:app --host 127.0.0.1 --port 8765 --no-server-header
```

Browse to the console (via your proxy once Phase 5 is done). On first launch it
shows a **one-time setup wizard** — create the initial **admin** account. After
that, log in (roles: Admin / Analyst / Viewer) and add analyst/viewer users
under user management.

---

## Phase 5 — Harden for production

**5a. Run it as a service** (`/etc/systemd/system/segs.service`):

```ini
[Unit]
Description=SEGS Secure Email Gateway console
After=network.target

[Service]
User=segs
WorkingDirectory=/opt/segs/app
EnvironmentFile=/opt/segs/app/.env
ExecStart=/opt/segs/app/.venv/bin/uvicorn server.main:app --host 127.0.0.1 --port 8765 --no-server-header
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now segs
```

**5b. TLS reverse proxy** (nginx in front, terminating HTTPS, proxying to
`127.0.0.1:8765`). Once HTTPS is live, `SEG_COOKIE_SECURE=1` activates the
`Secure` cookie flag and HSTS.

**5c. What's already hardened for you** (from the VAPT pass — no action needed):
rate limiting + account lockout, PBKDF2 sessions, strict cookies, full security
headers (CSP/HSTS), disabled API docs, SSRF/XSS/path-traversal/log-injection
defenses, and owner-only secrets/quarantine storage that re-lock on every boot.

**5d. Restrict console access** to your SOC network (proxy allowlist / VPN /
firewall) — it's an admin tool, not a public site.

---

## Phase 6 — Tune detection before you enforce

Don't enable blocking against defaults. Calibrate first:

```bash
# Build a golden set: defanged real quarantine mail + known-good legitimate mail
python3 tests/run_eval.py samples/        # precision/recall on your corpus
```

- Adjust stage weights and verdict thresholds in `rules/weights.yaml`.
- Set protection policies in `rules/policy.yaml` (the 6 TMES-parity categories),
  or toggle them live in the console (Admin → policy).
- Re-run `run_eval.py` until precision/recall meet your targets.

---

## Phase 7 — Connect your mail flow

### 7A. Model A — Evaluation / shadow (ready now)

Point your mail system to export a copy of inbound mail as `.eml` into a hold
folder, then scan it:

```bash
# One message, or a whole directory — shadow mode logs the intended action but releases everything
SEG_ENFORCE=shadow python3 gateway/hold_consumer.py /path/to/held/mail/

# Review what SEGS *would* have done
python3 gateway/hold_consumer.py --list
python3 gateway/hold_consumer.py --reeval <queue_id>
```

Results land under `gateway/spool/` (`quarantine/`, `rejected/`, `released/`,
`shadow_logs/`) and appear in the console's live feed. This is a genuine,
risk-free production trial on your own traffic.

### 7B. Model B — Inline SMTP hold (integration work required)

The consumer logic is built (`gateway/hold_consumer.py`, `source="smtp_hold"`);
what you build is the **MTA adapter**:

1. Configure **Postfix/Rspamd** to HOLD inbound mail (e.g. Rspamd `soft reject`
   → hold queue, or a Postfix `hold` action) and write each message to the SEGS
   spool.
2. Implement an **`EnforcementClient`** (same Protocol as `LocalQuarantineClient`
   in `app/disposition.py`) that performs the real actions: **RELEASE** to the
   inbox path, **quarantine** to a mailbox/folder, or **550 REJECT**. Keep the
   spool (or a DB) for re-evaluation — never put SMTP calls in `verdict.py`.
3. Run `hold_consumer.py` as a service watching the hold queue.

This is the one piece that needs your infrastructure's specifics — I can help
build the adapter once your MTA is chosen.

### 7C. Model C — Post-delivery API (integration work required)

Build a small receiver that pulls delivered mail via the **Gmail API** or
**Microsoft Graph**, calls `run_pipeline(raw, source="gmail_api")`, and moves
malicious mail to a quarantine label/folder via the same API. Reuses the entire
detection core unchanged.

---

## Phase 8 — Graduate enforcement (the safety ramp)

Move one step at a time, watching the shadow logs / audit trail between steps:

```
SEG_ENFORCE=shadow      →   SEG_ENFORCE=quarantine   →   SEG_ENFORCE=reject
(log only, deliver all)     (hold SUSPICIOUS/MAL)         (may 550 MALICIOUS)
```

- Stay in **shadow** until false-positives on real mail are essentially zero.
- Move to **quarantine** (reversible — analysts release false positives from the
  console).
- Only enable **reject** after quarantine is proven, and even then it 550s
  MALICIOUS only if `rules/disposition.yaml` sets `allow_reject_on_malicious: true`.
  A 550 loses mail permanently; a quarantine is recoverable.

---

## Phase 9 — Operations

- **Analyst workflow:** triage the live feed; release / keep-blocked / re-evaluate
  / download quarantined mail from the console. Every action is audit-logged.
- **Re-evaluation:** `hold_consumer.py --reeval-all` re-scans held mail as
  detection improves; `--auto-release` frees anything now-benign.
- **Deep investigation:** upload any `.eml` to the console's Analyze page for the
  full forensic report (needs `SEG_GLM_CREDENTIALS_PATH`).
- **Monitoring:** alert on lockout / repeated-401 spikes in the activity audit
  log; watch `gateway/spool/shadow_logs/`.
- **Backups:** back up `data/` (users, sessions, correlation history) and
  `gateway/spool/` (quarantined evidence). Both are owner-only and gitignored.
- **Updates:** `git pull && pip install -r requirements.txt && pytest -q &&
  sudo systemctl restart segs`.

---

## Quick reference — the minimum viable deployment

```bash
# 1. Host
sudo apt install -y python3 python3-venv git

# 2. Install
git clone https://github.com/ronchaic/segs-secure-email-gateway.git && cd segs-secure-email-gateway
python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt

# 3. Configure (safe defaults)
echo "SEG_ENFORCE=shadow" > .env

# 4. Run the console → create admin in the setup wizard
uvicorn server.main:app --host 127.0.0.1 --port 8765 --no-server-header

# 5. Trial detection on your mail, risk-free
python3 gateway/hold_consumer.py /path/to/exported/mail/
python3 gateway/hold_consumer.py --list
```

Then tune (Phase 6), harden (Phase 5), and graduate enforcement (Phase 8).
