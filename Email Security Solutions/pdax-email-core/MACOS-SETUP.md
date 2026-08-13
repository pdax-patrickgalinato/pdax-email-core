# Running the Email Analyzer on macOS

Written for macOS specifically. Should take about five minutes.

---

## Step 1 — Open Terminal

Press **⌘ + Space**, type `Terminal`, press Return.

A window with a text prompt appears. Every command below gets typed here,
followed by Return.

---

## Step 2 — Check you have Python

```bash
python3 --version
```

**If you see `Python 3.9` or higher** — skip to Step 3.

**If a popup appears** saying "The python3 command requires the command line
developer tools" — click **Install** and wait a few minutes. That's Apple's
own toolchain; it's safe. Then re-run the command.

**If you see `Python 3.8` or older**, install a newer one with Homebrew:

```bash
brew install python
```

(No Homebrew? Get it at brew.sh, or download Python from python.org — either
works.)

---

## Step 3 — Unzip and enter the folder

Double-click `pdax-email-core.zip` in Finder. macOS creates a
`pdax-email-core` folder next to it.

Now tell Terminal to go there. **The easy way:** type `cd ` (with a space),
then **drag the folder from Finder into the Terminal window** — the path
fills itself in. Press Return.

```bash
cd /Users/yourname/Downloads/pdax-email-core
```

Confirm you're in the right place:

```bash
ls
```

You should see `analyze.py`, `app`, `rules`, `samples`. If not, you're in the
wrong folder.

---

## Step 4 — Set up a virtual environment

macOS protects its system Python, so installing packages directly often fails
with an **"externally-managed-environment"** error. A virtual environment
avoids this entirely and keeps everything self-contained in the project folder.

**Use Homebrew's Python 3.12, not the plain `python3` command.** macOS's
built-in system Python is 3.9, which reached end-of-life — some packages
(like the Gemini AI library) print end-of-life warnings on every run with it.
If you don't already have it: `brew install python@3.12`.

```bash
/opt/homebrew/bin/python3.12 -m venv .venv
source .venv/bin/activate
```

Your prompt now starts with `(.venv)` — that means it worked.

```bash
pip install -r requirements.txt
```

Two small packages install. Done.

> **Remember:** every new Terminal window needs `source .venv/bin/activate`
> again before running the program. If you get `ModuleNotFoundError`, that's
> almost always the reason.

---

## Step 5 — Run it

```bash
python3 analyze.py samples/phish_lookalike.eml
```

You should see:

```
================================================================
  VERDICT: MALICIOUS   score=95.0
  HARD OVERRIDE: sender_lookalike_domain
================================================================
From    : "PDAX Security" <support@pd4x.ph>
Subject : Urgent: Your account will be suspended within 24 hours
...
```

Try the others:

```bash
python3 analyze.py samples/clean_normal.eml     # CLEAN
python3 analyze.py samples/bec_giftcard.eml     # MALICIOUS
```

**That's the whole setup.** Everything below is about using it on real mail.

---

## Getting a real email to test

You need the email saved as an `.eml` file.

**Gmail in a browser** (most reliable):
1. Open the email
2. Click **⋮** at the top-right of the message
3. **Download message** → lands in `~/Downloads` as `.eml`

**Apple Mail:** drag the message from your inbox onto the Desktop. macOS
writes out an `.eml` file.

**Outlook for Mac:** drag the message to the Desktop, same idea.

Then analyze it — use the drag trick again to avoid typing the path:

```bash
python3 analyze.py ~/Downloads/suspicious-email.eml
```

Type `python3 analyze.py ` then drag the `.eml` file into Terminal and press
Return. Handles spaces in filenames automatically.

---

## Analyzing a whole folder

```bash
for f in ~/Downloads/quarantine/*.eml; do
  printf "%-45s" "$(basename "$f")"
  python3 analyze.py "$f" | grep VERDICT
done
```

Or, if you've named files with `phish_` / `bec_` / `clean_` prefixes, get
accuracy numbers:

```bash
python3 tests/run_eval.py ~/Downloads/quarantine/
```

---

## macOS-specific gotchas

**`zsh: command not found: python3`**
Command Line Tools aren't installed. Run `xcode-select --install`.

**`error: externally-managed-environment`**
You skipped the virtual environment in Step 4. Go back and do it — it's the
correct fix on macOS, not a workaround.

**`ModuleNotFoundError: No module named 'pydantic'`**
New Terminal window, venv not active. Run `source .venv/bin/activate` first.
(Check: does your prompt show `(.venv)`?)

**`no such file or directory: samples/phish_lookalike.eml`**
You're not in the project folder. `cd` back into `pdax-email-core`.

**Finder won't show the `.venv` folder**
It's hidden because of the leading dot. Press **⌘ + Shift + .** in Finder to
show hidden files. You never need to open it manually.

**`.eml` files open in Mail when double-clicked**
Expected. Don't double-click them — just pass the path to the program.

---

## Reactivating later

Next time you come back to this:

```bash
cd ~/Downloads/pdax-email-core
source .venv/bin/activate
python3 analyze.py samples/phish_lookalike.eml
```

Three commands, every time.

---

## What about the AI stage?

It runs entirely offline using local keyword rules — no AI service required.
The `content_ai` stage works out of the box. If you connect a language model
later, only that one stage changes.

The `degraded` labels you'll see on the `sender` and `attachments` stages are
also expected offline: those checks ran, but couldn't reach live domain-age or
file-reputation services. The detection underneath still works.

---

## Next step

Once it's running, the real work is tuning. Pull 10–20 known-phishing emails
and 10–20 known-good ones, run them through, and see what it gets wrong. Then
edit the plain-text files in `rules/` (protected domains, VIP names, score
thresholds) and re-run `python3 tests/run_eval.py samples/` to confirm your
changes helped without breaking the clean cases.

See `QUICKSTART.md` for the full explanation of the output and the tuning
files.
