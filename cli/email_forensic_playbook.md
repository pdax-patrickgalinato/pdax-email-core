# 📧 **Advanced Email Attachment & URL Forensic Analysis Playbook (v2.0)**

---

## 🎯 Purpose

This playbook defines a **high-fidelity, adversarial-aware methodology** for analyzing:

- Email attachments (images, PDFs, executables, archives)
- Embedded and external URLs
- Full email context (headers, behavior, intent)

**Objective:** Detect phishing, malware delivery, and social engineering with **maximum accuracy and minimal false negatives**.

---

## 🧠 Core Principles

### 1. Assume Adversarial Intent

All inputs are hostile until proven otherwise.

### 2. Context > Content

A benign file in a malicious context is still malicious.

### 3. Correlation Over Isolation

No single signal is enough. Combine:

- Headers
- Attachments
- URLs
- Behavioral intent

### 4. Low Signal ≠ Safe

Absence of malware ≠ legitimacy.

---

## 🔍 Step 1 — Deep Attachment Metadata Analysis

Extract:

- Filename
- Extension (true vs displayed)
- MIME type vs magic bytes (file signature)
- File size
- Encoding
- Hashes (MD5, SHA256)
- Entropy (detect packing/obfuscation)
- Creation/modification timestamps
- EXIF (for images)
- Embedded objects (OLE, PDF objects)

### 🚩 Red Flags

**Size Anomalies**

- Image < 20 KB → likely lure/thumbnail
- PDF < 50 KB → empty or fake
- Office file unusually small → macro dropper

**Filename Tricks**

- Double extensions: `invoice.pdf.exe`
- Unicode homoglyphs
- Excessively long names
- Randomized strings

**Type Mismatch**

- `.jpg` but MIME = executable
- `.pdf` containing embedded scripts

---

## 🧪 Step 2 — Advanced File Type Risk Classification


| Type                      | Risk        | Notes                 |
| ------------------------- | ----------- | --------------------- |
| .exe / .dll / .bat / .ps1 | 🔴 Critical | Direct execution      |
| .js / .vbs / .hta         | 🔴 Critical | Script-based malware  |
| .docm / .xlsm             | 🔴 High     | Macro delivery        |
| .zip / .rar / .7z / .iso  | 🔴 High     | Container evasion     |
| .pdf                      | 🟡 Medium   | Can embed JS, links   |
| .html / .htm              | 🔴 High     | Credential harvesting |
| .img / .iso               | 🔴 High     | Malware mounting      |
| .jpg / .png               | 🟢 Low*     | Often phishing bait   |


⚠️ *Images are frequently used as **click lures**, not payloads*

---

## 🧬 Step 3 — Deep Attachment Content Analysis

### For PDFs

- Extract embedded URLs
- Detect JavaScript actions
- Check for launch actions
- Inspect object streams

### For Office Files

- Detect macros (VBA)
- Identify obfuscation patterns
- External template injection (remote loading)

### For Archives

- Recursively unpack
- Detect nested archives
- Identify password-protected payloads

### For All Files

- Run hash against threat intel feeds
- Check entropy (packed/encrypted)
- Extract strings for IOCs

---

## 🖼️ Step 4 — Image Behavioral Analysis

Evaluate:

### 1. Size vs Expectation

- Screenshot expected: 100KB–2MB
- < 20KB → suspicious lure

### 2. Visual Intent

- Fake UI elements (login screens, alerts)
- Blurred or cropped content
- “Click here” indicators

### 3. Context Correlation

- Inline image + **off-brand** external link → 🔴 HIGH RISK
- **Do not flag signature logos.** Image hyperlinks to the sender/recipient
  organization domain, or to common social/profile destinations (LinkedIn,
  Facebook, X/Twitter, Instagram, YouTube, etc.), are expected in email
  signatures and must remain unscored. Raise only when the destination is
  off-brand **and** an amplifier is present (URL shortener / image file-host,
  risky TLD, social-engineering framing, or bait-style screenshot filename).

### 4. Steganography Check (Advanced)

- Hidden payload indicators
- Abnormal entropy patterns

---

## 🔗 Step 5 — URL Extraction (Deep)

Extract from:

- Email body (HTML + plaintext)
- Attachments (PDF, Office, HTML)
- Image OCR (if needed)
- QR codes (if present)

Normalize:

- Decode URL encoding
- Resolve HTML entities
- Strip tracking parameters

---

## 🔍 Step 6 — URL Intelligence & Expansion

### 🔓 Expand All Shortened URLs

**Expanded Shortener List (Non-Exhaustive):**

[bit.ly](http://bit.ly)  
[tinyurl.com](http://tinyurl.com)  
[t.co](http://t.co)  
[goo.gl](http://goo.gl)  
[ow.ly](http://ow.ly)  
[buff.ly](http://buff.ly)  
[is.gd](http://is.gd)  
[soo.gd](http://soo.gd)  
[s2r.co](http://s2r.co)  
[cutt.ly](http://cutt.ly)  
[shorturl.at](http://shorturl.at)  
[rebrand.ly](http://rebrand.ly)  
[adf.ly](http://adf.ly)  
[clk.im](http://clk.im)  
[shorte.st](http://shorte.st)  
[bc.vc](http://bc.vc)  
[u.to](http://u.to)  
[lnkd.in](http://lnkd.in)  
[rb.gy](http://rb.gy)  
[v.gd](http://v.gd)  
[x.co](http://x.co)  
[psce.pw](http://psce.pw)  
[qr.ae](http://qr.ae)  
[trib.al](http://trib.al)  
[ift.tt](http://ift.tt)  
[dlvr.it](http://dlvr.it)  
[wp.me](http://wp.me)  
[amzn.to](http://amzn.to)  
[fb.me](http://fb.me)  
[youtu.be](http://youtu.be)  
[t.ly](http://t.ly)  
[clck.ru](http://clck.ru)  
[gg.gg](http://gg.gg)  
[chilp.it](http://chilp.it)  
[mcaf.ee](http://mcaf.ee)  
[po.st](http://po.st)

🚩 Treat ALL shorteners as **high-risk obfuscation layers**

---

### URL Component Analysis

**Domain**

- Newly registered domains
- Typosquatting
- IDN/punycode attacks
- Mismatch with sender

**Path**

- Random strings
- Keywords: login, verify, secure, update

**Query Parameters**

- Tokens, redirects, encoded payloads

**Fragments (#)**

- Used for deception (client-side manipulation)

---

## 🔄 Step 7 — Redirect Chain Analysis

Trace full path:

Initial → Intermediate → Final Destination

### 🚩 Indicators

- Multiple redirects (>2)
- Use of tracking domains
- Geo-based cloaking
- Different destinations per request

### Advanced Checks

- Compare HEAD vs GET responses
- Detect conditional redirects (User-Agent based)

---

## 🌐 Step 8 — Destination Page Analysis

If safe to analyze (sandboxed):

- Login form detection
- Brand impersonation
- SSL certificate anomalies
- Domain age vs brand age mismatch
- Form submission endpoints

---

## 🧠 Step 9 — Social Engineering Detection

### Message Patterns

- Generic greeting
- No personalization
- Urgency (“Act now”)
- Threats or rewards

### Behavioral Intent

- Click link
- Download file
- Enter credentials

### Attachment Framing

- “See attached”
- “View screenshot”
- “Important document”

---

## 🔐 Step 10 — Authentication Correlation

Check:

- SPF
- DKIM
- DMARC
- ARC

### 🚩 Signals

- DKIM fail → content tampering
- SPF fail → spoofing
- ARC fail → broken trust chain

---

## 🧩 Step 11 — Correlation Engine (Decision Logic)

### Example Rule:

IF:

- URL shortener present
- Redirect chain detected
- Suspicious domain
- Social engineering language
- Attachment lure

THEN:  
→ 🔴 **Phishing (High Confidence)**

---

## 📊 Step 12 — Advanced Risk Scoring


| Factor                  | Score |
| ----------------------- | ----- |
| Suspicious domain       | +30   |
| URL shortener           | +25   |
| Redirect chain          | +20   |
| Newly registered domain | +25   |
| DKIM/SPF fail           | +20   |
| Social engineering      | +25   |
| Suspicious attachment   | +20   |
| Embedded script/macro   | +30   |
| Obfuscation detected    | +20   |


### Thresholds

- 0–30 → Low
- 31–60 → Medium
- 61–100 → High
- 100+ → Critical

---

## 🧠 Step 13 — Final Classification

Choose ONE:

- ✅ Legitimate
- ⚠️ Suspicious
- 🔴 Phishing
- 🔴 Malware Delivery

---

## 🛡️ Step 14 — Response Actions

### High / Critical

- Block domains & IPs
- Quarantine email
- Extract IOCs:
  - URLs
  - Domains
  - Hashes
  - Filenames

### Medium

- Flag for analyst review
- Warn user

### Low

- Log for telemetry

---

## 📌 Key Insight

**Attachments are often not the payload — they are the trigger.**  
**Links are often not the destination — they are the disguise.**

---

## 🚀 Standard Output Format

### Summary

What the email is doing

### Technical Findings

- Attachment analysis
- URL analysis
- Redirect behavior
- Authentication

### Risk Assessment

Score + classification

### Verdict

Final conclusion

### Actions

Recommended response

---

## 🧠 Golden Rule

**If something tries to make the user click —**  
**analyze the destination, not the decoy.**