# QUICKSTART — Running the Email Analyzer

A step-by-step guide for anyone on the team. No AWS, no cloud accounts, no API
keys needed. This runs entirely on your own laptop and analyzes email files
you already have.

---

## What this program does

You give it an email file (`.eml`). It tells you whether that email is
phishing, and *why* — which checks fired, what the risk score was, and what
indicators (domains, URLs, file hashes) to block.

Think of it as running the manual phishing-analysis checklist automatically.

---

## Before you start

You need **Python 3.9 or newer** to run this. That said, if you're on macOS:
**use Homebrew's Python (3.12+), not the plain `python3` command** — macOS's
built-in system Python is 3.9, which reached end-of-life, and some packages
(the Gemini AI library) print end-of-life warnings on every run with it.

```bash
python3 --version
```

If you see `Python 3.9.x`, that'll run, but on macOS prefer installing a
current version instead:

- **macOS:** `brew install python@3.12`, then use `/opt/homebrew/bin/python3.12` when creating the virtual environment (see `MACOS-SETUP.md`)
- **Windows:** download from python.org, and **tick "Add Python to PATH"** during install. Use `python` instead of `python3` in every command below.
- **Linux:** `sudo apt install python3 python3-pip`

---

## Step 1 — Get the files onto your machine

Unzip `pdax-email-core.zip` somewhere you can find it, then open a terminal
and move into that folder:

```bash
cd path/to/pdax-email-core
```

You should see `analyze.py` when you run `ls` (or `dir` on Windows). If you
don't, you're in the wrong folder.

---

## Step 2 — Install the two dependencies

```bash
pip install -r requirements.txt
```

That's it — just `pydantic` and `PyYAML`. Everything else uses Python's
built-in libraries.

> **If `pip` isn't found**, try `pip3` or `python3 -m pip install -r requirements.txt`.
>
> **On newer Ubuntu/Debian**, if you get an "externally-managed-environment"
> error, add `--break-system-packages`:
> `pip install -r requirements.txt --break-system-packages`

---

## Step 3 — Run your first analysis

Three example emails ship with the program. Start with the obvious phish:

```bash
python3 analyze.py samples/phish_lookalike.eml
```

You should see something like this:

```
================================================================
  VERDICT: MALICIOUS   score=95.0
  HARD OVERRIDE: sender_lookalike_domain
================================================================
From    : "PDAX Security" <support@pd4x.ph>
Subject : Urgent: Your account will be suspended within 24 hours

Stages:
  [      ok] headers      score= 90.0  spf_fail, dmarc_fail, return_path_mismatch
  [degraded] sender       score=100.0  lookalike_of:pdax.ph, vip_name_spoof:PDAX
  [      ok] urls         score= 50.0  anchor_href_mismatch, url_risky_tld:top
  [ skipped] attachments  score=  0.0  -
  [      ok] content_ai   score= 55.0  urgency_language, credential_request
  [      ok] intel        score=  0.0  -

Reasons: lookalike_of:pdax.ph
```

**It worked.** Now try the other two:

```bash
python3 analyze.py samples/clean_normal.eml     # should say CLEAN
python3 analyze.py samples/bec_giftcard.eml     # should say MALICIOUS
```

---

## Step 4 — Read the output

**VERDICT** is the answer. Four possible values:

| Verdict | Meaning | Disposition (SEG) |
|---|---|---|
| `CLEAN` | Nothing suspicious found | `DELIVER` |
| `LOW` | Minor oddities, probably fine | `LOG` (deliver + audit) |
| `SUSPICIOUS` | Needs a human to look | `QUARANTINE` |
| `MALICIOUS` | Confident this is an attack | `QUARANTINE` (+ IOC block later); `REJECT` only when explicitly enabled |

Policy lives in `rules/disposition.yaml`. Default enforce mode is **shadow**
(`PDAX_ENFORCE=shadow`) — the hold consumer logs what it *would* do and still
releases mail. See `gateway/README.md`.

**HARD OVERRIDE** (only appears sometimes) means one check was so conclusive
that the program skipped the scoring math entirely. `sender_lookalike_domain`
means the sender used a domain designed to look like yours — that alone is
enough, no further debate.

**Stages** shows each check and what it found:

- `ok` — the check ran normally
- `skipped` — nothing to check (e.g. `urls` is skipped when the email has no links)
- `degraded` — the check ran but couldn't reach an external service. Expected on your laptop: `sender` and `attachments` show `degraded` because live domain-age and VirusTotal lookups aren't wired up offline. **This is normal, not an error.**
- `error` — that check crashed. The rest of the pipeline still ran.

**Reasons** is the plain-language summary of why it reached that verdict.

**IOCs** at the bottom are the indicators you'd feed into Wazuh or your
blocklists.

---

## Step 5 — Analyze your *own* suspicious email

This is the useful part. You need the email as an `.eml` file.

**From Gmail (web):**
1. Open the suspicious email
2. Click the **⋮** (three dots) at the top right of the message
3. Choose **Download message**
4. It saves as a `.eml` file

**From Outlook:** File → Save As → choose "Outlook Message Format" or drag the
email from your inbox onto your desktop.

Then point the program at it:

```bash
python3 analyze.py ~/Downloads/suspicious-email.eml
```

> **Tip:** if the filename has spaces, wrap it in quotes:
> `python3 analyze.py "~/Downloads/weird email.eml"`

---

## Step 6 — Analyze a whole folder at once

Got a batch of quarantined emails to triage?

```bash
for f in /path/to/emails/*.eml; do
  printf "%-40s" "$f"
  python3 analyze.py "$f" | grep VERDICT
done
```

Or use the built-in evaluation harness, which also scores accuracy if you name
your files with `phish_`, `bec_`, or `clean_` prefixes:

```bash
python3 tests/run_eval.py /path/to/emails/
```

---

## Other output formats

```bash
python3 analyze.py samples/phish_lookalike.eml --json    # one-line audit record
python3 analyze.py samples/phish_lookalike.eml --slack   # Slack message payload
```

The `--json` output is what you'd append to an audit log file — one line per
email analyzed, which is your evidence trail for a BSP examination.

---

## Making it yours

Three plain-text files in the `rules/` folder control the detection. Edit them
with any text editor — no code changes needed.

**`rules/protected_domains.txt`** — domains attackers might imitate. Anything
one character away from these gets flagged as a lookalike. Add your partner
and vendor domains:

```
pdax.ph
fireblocks.com
circle.com
yourbank.com.ph
```

**`rules/vip_names.txt`** — names used in impersonation attacks. If a display
name contains one of these but the email doesn't come from a protected domain,
that's a red flag:

```
PDAX
CEO
finance
```

**`rules/weights.yaml`** — how much each check counts, and the score cutoffs
for each verdict. Lower `malicious: 70` to catch more (and get more false
positives); raise it to be stricter.

After any edit, re-run the tests to make sure you didn't break anything:

```bash
python3 tests/test_core.py
python3 tests/run_eval.py samples/
```

---

## Troubleshooting

**`ModuleNotFoundError: No module named 'pydantic'`**
You skipped Step 2, or installed into a different Python. Run
`python3 -m pip install -r requirements.txt`.

**`python3: command not found`**
On Windows use `python` instead. Otherwise Python isn't installed or isn't on
your PATH.

**`FileNotFoundError: samples/phish_lookalike.eml`**
You're not in the program folder. `cd` into the unzipped `pdax-email-core`
directory first.

**`can't open file 'analyze.py'`**
Same thing — wrong folder. Run `ls` and check you can see `analyze.py`.

**Everything shows `degraded`**
That's expected offline. The deterministic checks (headers, sender lookalikes,
URLs, attachment types) all still work — those are the ones that catch most
phishing anyway.

**The program says CLEAN but I'm sure it's phishing**
Two things to check: is the sender's domain in `protected_domains.txt`? And
does the email actually contain the signals (bad SPF, lookalike domain,
suspicious link)? Some phishing is genuinely subtle — that's what the tuning
process is for. Add the email to your test corpus with a `phish_` prefix and
adjust `weights.yaml` until it's caught, then re-run the eval to confirm you
didn't break the clean cases.

---

## A note on the AI stage

The `content_ai` stage currently uses simple keyword rules that run locally, so
the program works with no AI service at all. If you later connect a language
model, only that one stage changes — everything else stays exactly as it is.

---

## What to do next

1. Run it against 10–20 real emails you already know are phishing, plus 10–20
   you know are legitimate.
2. Note anything it gets wrong.
3. Adjust `rules/` and re-run `tests/run_eval.py` until the numbers look right.

That tuning process *is* the work. The code is done; teaching it what PDAX
traffic looks like is what makes it accurate.
