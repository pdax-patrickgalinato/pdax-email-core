# PDAX Email Security Project — Checkpoint Report (Plain-Language)

**Checkpoint date:** 2026-08-02
**Audience:** anyone without a programming background

---

## 1. What is this project?

PDAX currently uses a third-party product, Trend Micro Email Security
(TMES), to filter phishing and scam emails before they reach staff inboxes.
During testing, we found a real phishing email that had **already been
scanned and passed by TMES** — and it was still a scam. That's the reason
this project exists: **build our own email-scanning system that PDAX fully
controls**, so we're not solely dependent on one vendor's filter, and so it
reflects the specific scams that actually target PDAX and the crypto
industry.

Think of it as a second, custom-built pair of eyes looking at every email —
one we can teach, tune, and improve ourselves, instead of waiting on a
vendor's update cycle.

## 2. What's the plan?

We're building this in stages, in order of what matters most first:

1. **Get the "brain" right first** — the actual logic that decides whether
   an email is dangerous. This is what we've been working on.
2. **Test it quietly in the background** — watch real mail flow through it
   without touching anything, just to see if it agrees with what's actually
   safe or dangerous. (Not started yet — comes after step 1 is trusted.)
3. **Only then, let it act** — put it in a position where it can actually
   block or quarantine a dangerous email before it reaches someone's inbox.

We deliberately have **not** skipped ahead to step 3. A system that can block
real email needs to prove itself first — a mistake at that stage means lost
legitimate mail, which is its own kind of damage.

## 3. How does the "brain" decide?

The system looks at an email through several independent checks — who it's
really from, whether the links go where they claim to, whether attachments
look dangerous, and whether the wording itself matches known scam patterns
(urgency, fake invoices, fake login pages, etc.). Each check produces a
score, and a scoring engine combines them into one final verdict: Clean, Low
Risk, Suspicious, or Malicious.

One important design rule: **an AI model is only ever allowed to contribute
an opinion/score — it can never make the final call by itself.** A separate,
predictable set of rules always makes the actual decision. This matters
because it means a cleverly-worded scam email can't "trick" the AI into
waving it through — the AI's opinion is just one input among several, and
the rules around it are designed so that no single fooled input can flip a
dangerous email to "safe."

## 4. What did we actually accomplish this checkpoint?

**We connected the system to a real AI assistant to help read email content**
— both Anthropic's Claude (via Amazon's cloud, hosted in the Singapore
region) and Google's Gemini (using the company's paid subscription) are now
wired in as options, so either can be switched on with a setting. Neither is
turned on by default, and neither has been tested against a live account yet
— both still need real API access to actually try.

**Important flag on Gemini specifically:** the version PDAX currently has
access to (a standard paid API key) does not guarantee the email content
stays within a specific country/region, and has weaker data-handling
guarantees than an enterprise-grade option would. Since PDAX is a
BSP-regulated company subject to the Data Privacy Act, **this needs sign-off
from the Data Protection Officer before it's used on real staff or customer
emails.** We built it so it's off by default specifically so that approval
can happen without blocking the rest of the work.

**We tested the system against real, actual phishing emails** — not just
made-up test examples. One of them (a fake "please sign this document"
email that was actually confirmed as phishing by an outside security team)
exposed a real gap: our system scored it as low-risk when it should have
flagged it as dangerous. We found the reason, fixed it with three new
detection rules that are general enough to catch similar future scams (not
just a patch for this one email), and confirmed the fix didn't cause the
system to start wrongly flagging safe emails. That email is now permanently
part of our test set, so this exact mistake can never silently come back.

**We did a security audit of our own code** — because a tool built to catch
scams is itself a target worth protecting. We checked:
- Whether any of the outside code libraries we use have known security
  problems (a real, current concern — several unrelated companies had
  their software supply chains compromised earlier this year). **Good
  news: the libraries this project actually depends on are clean.**
- Whether our own code has any weaknesses. We found and fixed one real
  issue: a maliciously-crafted email subject line could have been used to
  visually mess with what a security analyst sees on their screen while
  reviewing it, or to trigger an unwanted mass notification in Slack. Fixed.
- We also found (but can't fully fix yet) a minor, low-probability weakness
  tied to a required software component for the Amazon/Claude connection —
  it's a known limitation of running on the older, more compatible version
  of the programming language this project intentionally uses for
  compatibility with the company's laptops. It's documented and low-risk in
  practice, not an active problem.

## 5. Where do things stand right now?

The system is currently catching **100% of the test phishing emails and
100% of the test legitimate emails** we've thrown at it (a small but growing
set, now including one real confirmed scam). That's a strong sign the
underlying logic is sound — but it's still a small test set, and the real
proof will come from testing against a larger volume of PDAX's actual mail.

## 6. What's left / what needs a decision from someone

1. **One real email's status is still unconfirmed** — we need someone to
   confirm whether a specific test email (a login-notification message from
   a company called "Agora") is legitimate or not, so we know if the system
   got it right.
2. **The biggest remaining improvement**: connecting to real threat-
   intelligence services (databases of known-bad websites/senders) — this
   is not done yet and is the single most impactful thing left to build.
3. **A privacy sign-off is needed** before the Google Gemini option can be
   used on real emails, per the note above.
4. **Neither AI option has been tried against a live account yet** — that's
   the next practical step once access is confirmed.
