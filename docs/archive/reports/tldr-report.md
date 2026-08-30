# TL;DR — PDAX Email Security Project Checkpoint

**Date:** 2026-08-02

**What this is:** an in-house phishing-detection engine PDAX is building to
stop relying solely on Trend Micro Email Security — triggered by a real
phishing email that passed TMES and was still malicious.

**What's done:**
- Core detection engine works: 10-stage pipeline, deterministic scoring,
  AI is advisory-only (can never single-handedly clear a malicious email).
- Two AI backends wired in and tested (Claude/AWS Bedrock, Gemini/Google AI
  Studio) — both off by default, neither run against a live account yet.
- Tested against real phishing, not just made-up samples — found and fixed
  a real miss (scored LOW, should've been MALICIOUS) with 3 new general
  detection rules. Now a permanent regression test.
- Full security review done: dependencies clean, one real code
  vulnerability found and fixed (terminal/Slack injection via crafted email
  headers), one low-risk structural limitation documented (not fixable
  without dropping Python 3.9 support).

**Current score:** 100% precision/recall on the test set (7 samples, 4
confirmed phish including one real-world case, 3 confirmed clean).

**Needs a decision from you:**
1. Confirm ground truth on one pending test email (`agora.eml`).
2. DPO sign-off (RA 10173) before Gemini touches real mail.

**Biggest thing left to build:** real threat-intelligence lookup
(VirusTotal/AbuseIPDB) — currently a stub, and the single highest-impact
gap remaining.

**Not started yet, by design:** the parts that actually touch live mail
(monitoring inbox, or blocking at the gateway) — intentionally last, after
detection logic is proven.
