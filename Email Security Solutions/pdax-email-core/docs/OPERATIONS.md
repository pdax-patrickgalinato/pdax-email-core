# SEGS — SOC Operations Guide

This guide is for SOC analysts who review and manage email threats in the SEGS dashboard. It covers the day-to-day workflow: reviewing the live feed, managing quarantined mail, handling false positives, and managing users and settings.

---

## Accessing the dashboard

**URL**: `https://segs.pdax.ph` (accessible only from the JumpCloud VPN)

Connect to VPN first. If the page does not load, confirm VPN connectivity before reporting an issue.

Default credentials are created on first deployment. Change them immediately via Settings → Users.

---

## Dashboard overview

The dashboard has five main sections:

| Section | What it shows |
|---------|-------------|
| **Feed** | Live stream of all scanned emails with verdicts |
| **Quarantine** | Emails currently held for review (SUSPICIOUS / MALICIOUS) |
| **Enforcement** | Current blocking mode and spool statistics |
| **Settings** | Notification config, user management, policy |
| **Activity** | Audit log of all admin actions |

---

## The Feed

The Feed shows every email SEGS has analyzed, in reverse chronological order. Each entry shows:

- **Verdict** badge: CLEAN (green), LOW (blue), SUSPICIOUS (amber), MALICIOUS (red)
- **Sender** and **subject**
- **Recipient** mailbox
- **Timestamp**
- **Key findings** (top signals that drove the verdict)

### Interpreting verdicts

| Verdict | Meaning | Action |
|---------|---------|--------|
| CLEAN | No suspicious signals | No action needed |
| LOW | Minor signals, likely safe | Review if volume spikes |
| SUSPICIOUS | Multiple signals; possible threat | Review the email detail, decide quarantine vs release |
| MALICIOUS | Strong threat indicators; hard-override signals present | Confirm block; escalate to incident response if widespread |

### Drilling into a detection

Click any Feed entry to see the full analysis report:

- **Score breakdown**: each finding with its weight contribution
- **Stage results**: what each of the 10 pipeline stages found
- **Raw email headers**: formatted for readability
- **URLs**: extracted with risk annotation
- **Attachments**: file names, types, hashes, VirusTotal result
- **Content AI analysis**: GLM verdict summary

---

## Managing quarantined mail

Emails with SUSPICIOUS or MALICIOUS verdicts (in `quarantine` enforcement mode) are removed from the recipient's inbox and held in the quarantine spool.

### Reviewing quarantine

1. Go to **Quarantine** tab
2. Click an entry to view the full analysis report
3. Read the original email (rendered safely — all links are defanged)

### Releasing a false positive

If you determine the email is safe (false positive):

1. Click **Release** on the email detail page
2. The email is moved back to the recipient's inbox
3. The release is logged in the activity audit

Before releasing, consider:
- Is the sender known? Check against trusted senders.
- Did the URL/attachment analysis flag a genuine threat?
- Is this a one-off or part of a pattern?

### Confirming a block

If the email is genuinely malicious:

1. Click **Confirm Block** — the email moves to the rejected spool
2. Add the sender domain to the blocklist (Settings → Blocklist) if needed
3. If MALICIOUS and targeted (BEC, credential phishing): escalate to the incident response workflow

### Re-evaluating with updated rules

After tuning weights or lists, you can re-run the pipeline on quarantined emails without re-fetching:

```bash
# From within the VPN (or on the ECS task directly):
python3 gateway/hold_consumer.py --reeval <queue_id>
python3 gateway/hold_consumer.py --reeval-all
```

Each re-evaluation appends to `meta.json`'s `reeval_history[]` — the full audit trail is preserved.

---

## Enforcement modes

The current enforcement mode is shown in the **Enforcement** tab.

| Mode | Effect | When to use |
|------|--------|------------|
| `shadow` | All mail delivered normally; SEGS logs what it would have done | Initial deployment, tuning phase |
| `quarantine` | SUSPICIOUS and MALICIOUS mail removed from inbox and held | Normal operations |
| `reject` | As quarantine; MALICIOUS mail may also trigger an SMTP 550 reject (Path B only) | After Path B is live |

To change the mode:
1. Update `SEG_ENFORCE` in AWS Secrets Manager → `segs/prod`
2. Run `bash deploy/update-service.sh` to force a new ECS deployment

**Do not switch to `quarantine` mode without first running in `shadow` mode for at least 2 weeks** to establish a false-positive baseline.

---

## Managing users

Go to **Settings → Users**.

### Adding an analyst account

1. Click **Add User**
2. Set a username and a strong temporary password
3. Assign role: `analyst` (read + quarantine actions) or `admin` (full access)
4. Share credentials securely; require the analyst to change their password on first login

### Roles

| Role | Permissions |
|------|-------------|
| `viewer` | Read-only: Feed, Quarantine (view only) |
| `analyst` | Feed, Quarantine (release/block), Settings (view only) |
| `admin` | All, including Settings (users, policy, notification config, lists) |

### Removing access

Click the user → **Deactivate**. Sessions are invalidated immediately. Deactivated accounts appear in the audit log for 90 days before deletion.

### After a staff departure

1. Deactivate the account immediately
2. Rotate the SEGS session secret if the departing user had admin access:
   - Update `SEG_SECRET_KEY` in Secrets Manager
   - Force redeploy (`bash deploy/update-service.sh`) — this invalidates all existing sessions

---

## Notification configuration

### Slack alerts

Go to **Settings → Notifications → Slack**:

1. **Webhook URL**: your Slack app's incoming webhook URL for the SOC channel
2. **Minimum severity**: set to `SUSPICIOUS` for most teams (or `MALICIOUS` for lower noise)
3. Click **Save** and **Test**

SEGS sends a structured Slack alert for each email that meets the minimum severity. The alert includes sender, subject, verdict, score, and a link to the feed entry.

### Email notifications (quarantine alerts)

Go to **Settings → Notifications → Email**:

1. **SMTP host**: `smtp.gmail.com:587` (or your Workspace relay)
2. **From address**: `segs-alerts@pdax.ph`
3. **To address**: `security@pdax.ph` (or a distribution list)
4. The SMTP password is stored in `SEGS_NOTIFY_SMTP_PASS` in Secrets Manager — never entered here

SEGS sends a notification email to the email recipient when their message is quarantined, informing them that a message was held and who to contact for release.

---

## Managing allow/block lists

Go to **Settings → Lists**.

| List | Effect |
|------|--------|
| **Trusted senders** | Emails from these addresses bypass all scoring (verdict = CLEAN) |
| **Trusted domains** | Domains that are PDAX partners — reduces edit-distance false positives |
| **Blocked senders** | Always quarantined regardless of score |
| **Blocked domains** | Always quarantined regardless of score |
| **Risky TLDs** | Domains with these TLDs get extra penalty in URL scoring |
| **Banned extensions** | Attachments with these extensions are always flagged |

Source files: `rules/trusted_senders.txt`, `rules/trusted_domains.txt`, `rules/blocked_senders.txt`, etc.

Changes made in the dashboard UI take effect immediately (no redeploy needed). Changes to the source YAML/text files in the repo require a redeploy.

---

## Tuning detection weights

SEGS detection weights are in `rules/weights.yaml`. Each finding type maps to a numeric score contribution.

**Recommended tuning process:**

1. Run in `shadow` mode for 2 weeks
2. Export the Feed data: Settings → Export Feed (CSV)
3. Identify false positives (SUSPICIOUS/MALICIOUS verdicts on known-safe mail)
4. Note which finding types drove the false positive score
5. Lower the weight for those finding types in `weights.yaml`
6. Identify false negatives (CLEAN verdicts on known-bad mail) and raise weights correspondingly
7. Commit the updated `weights.yaml` and redeploy

**Do not lower a weight below 0.5 without understanding why the signal triggered.** Some findings are intentionally high-weight because they correlate strongly with real attacks even at low base rates (e.g., `vip_display_name_spoof`, `vt_malicious`).

---

## Activity audit log

Every admin action is written to `data/activity_audit.jsonl`. To view recent activity:

1. Go to **Activity** tab in the dashboard
2. Filter by user, action type, or date range

Actions logged:
- Login / logout / failed login / lockout
- Email release (quarantine → inbox)
- Email confirm-block
- User create / deactivate / role change
- Enforcement mode change
- List add / remove
- Settings save
- Watch register / renew

The audit log is append-only within the application. To prevent tampering, the file is on EFS and CloudWatch Logs streams a copy to `/segs/dashboard` log group automatically.

---

## Incident response integration

When SEGS detects a MALICIOUS email (especially BEC or credential phishing):

1. Confirm block the quarantined message
2. Note all IOCs (sender domain, IPs, URLs, attachment hashes) from the analysis report
3. Run an IOC search across the Feed: click a domain/IP/hash → "Search Feed for this IOC"
4. If the same IOC appears in multiple emails: escalate to the full IR playbook
5. Add the sender domain to the blocked domains list
6. If a user's account may be compromised: escalate to IT for credential reset and session revoke

Escalation contact: `security@pdax.ph`

---

## Monitoring and alerts

### CloudWatch dashboards

| Dashboard | Contents |
|-----------|----------|
| SEGS Feed | Pipeline throughput, verdict distribution, quarantine count |
| SEGS Reliability | ECS task health, container restart count, ALB 5xx rate |

### Key operational alerts (already configured in CloudWatch)

| Alert | Meaning |
|-------|---------|
| `segs-dashboard-unhealthy` | Dashboard ECS task not healthy → escalate to ops |
| `segs-receiver-unhealthy` | Receiver ECS task not healthy → Gmail notifications not being processed |
| `segs-watch-renewal-failed` | Gmail watch expired for a mailbox → mail not being scanned |
| `segs-auth-failures` | ≥5 failed logins in 5 minutes → possible credential stuffing attempt |

All alerts → SNS → `security@pdax.ph` + Wazuh SIEM.

---

## URL analysis — how SEGS inspects links

SEGS analyses every URL in every email through two safe layers. **No link is ever opened or fetched from the SEGS machine itself.** `SEG_LANDING_FETCH` is permanently disabled (`0`) in all environments — do not change it.

### Layer 1 — VirusTotal URL submission (always active when `SEG_INTEL_CLIENT=vt_abuseipdb`)

Each URL is submitted to the VirusTotal API. VT's own infrastructure fetches and scans the URL — SEGS only sends the URL string and receives a reputation score back. Known-bad URLs produce an `intel_url:` flag and the `threat_intel_hit` hard override (verdict = MALICIOUS, score = 100).

URLs not yet in VT's database are submitted for background scanning and return results on the next email containing that URL. The VT submission uses the same quota budget as hash/domain/IP lookups — see §VirusTotal / AbuseIPDB quota exhaustion below if the budget is regularly exhausted.

### Layer 2 — ClamAV URL signature scan (active when `SEG_SANDBOX_PROVIDER=clamav`)

Each URL's bytes are sent to the local `clamd` daemon via `scan_stream`. ClamAV checks the URL string against its URL-based signature database: URLhaus blocklist, known phishing domains, malware-distribution URL patterns. This is a **local signature lookup — zero outbound connection from SEGS**.

A ClamAV URL hit produces an `intel_url_clam:` flag and the same `threat_intel_hit` hard override as a VT URL match. If clamd is not running, this layer skips silently — VT URL checking continues unaffected.

### What this means for phishing links

A phishing URL in an email will:
1. Be checked against VT's reputation database (if `SEG_INTEL_CLIENT=vt_abuseipdb`)
2. Be checked against ClamAV's URL signatures locally (if `SEG_SANDBOX_PROVIDER=clamav`)
3. **Never be opened or fetched by the SEGS machine** — the attacker's server never receives a connection from SEGS infrastructure

If neither VT nor ClamAV flag a URL (novel phishing not yet in any database), the URL analysis stage still runs heuristics: display/href mismatch detection, suspicious TLD scoring, brand-keyword lookalike matching, and IP-literal URL detection. These run offline with no external calls.

---

## VirusTotal / AbuseIPDB quota exhaustion

### What it means

When SEGS exhausts the daily lookup quota for VirusTotal or AbuseIPDB (HTTP 429 from the provider), it sets a **process-level backoff flag** that pauses intel lookups for that provider for one hour. This prevents the pipeline from blocking on every subsequent email during the quota window.

**Indicators in the dashboard:**

| Location | What you see |
|----------|-------------|
| Analyze tab | Yellow warning banner: *"⚠️ API quota limit reached: VirusTotal …"* |
| Full Markdown Report | Blockquote under *SEGS Gateway Analysis* with a note about incomplete coverage |
| API response | `quota_flags: ["quota_exhausted_vt"]` and/or `["quota_exhausted_abuseipdb"]` |

Emails scanned during the quota window receive a **complete heuristic pipeline result** (header, sender, URL, attachment, content AI stages all run normally) but **threat-intel lookups are skipped** for affected indicators. The verdict is based on the heuristic score alone.

### How long it lasts

The backoff flag expires automatically **one hour after the 429 was first detected** (within the same uvicorn process). On process restart (ECS task restart or redeploy), the flag resets immediately regardless of the quota window.

Note: the underlying API quota itself resets at **midnight UTC** (VirusTotal free tier). A process restart before midnight does not restore quota capacity — it only clears the in-memory flag, which means the next email will re-discover the 429 and re-set the flag for another hour.

### What to do

| Situation | Action |
|-----------|--------|
| Occasional quota exhaustion | No action needed — the backoff self-heals. Monitor the frequency. |
| Daily exhaustion on most active days | Lower `SEG_VT_MAX_INDICATORS_PER_EMAIL` in Secrets Manager (`3–4` instead of `8`) to stretch the quota across more emails. |
| Persistent exhaustion blocking threat coverage | Upgrade to a paid VirusTotal and/or AbuseIPDB tier. Update the API keys in Secrets Manager (`segs/prod`). |
| Need immediate intel lookup during quota window | Force an ECS task restart (`bash deploy/update-service.sh`) — the flag clears on restart. Only do this if the API quota has also reset (after midnight UTC), otherwise the flag will be re-set on the first 429. |

---

## Wazuh SIEM log shipping

SEGS ships audit logs to S3 as gzip-compressed JSONL batches so Wazuh (or any S3-sourced SIEM) can ingest them. This feature activates automatically when `SEG_S3_BUCKET` is set in Secrets Manager.

### What gets shipped

| Log source | Content |
|-----------|---------|
| **Activity audit** (`data/activity_audit.jsonl`) | All admin actions: login, email release/block, user management, settings changes, enforcement mode changes |
| **Shadow enforcement** (`gateway/spool/shadow_logs/shadow_enforcement.jsonl`) | Emails that would have been quarantined or rejected in shadow mode |

Each record is tagged `"wazuh": true`. S3 key format: `{SEG_S3_PREFIX}/{source}/{YYYY}/{MM}/{DD}/{HHMMSS}-{uuid}.jsonl.gz`

### Monitoring the shipper

The shipper logs to the container's stderr (CloudWatch → `/segs/dashboard`):

```
wazuh_shipper: disabled (SEG_S3_BUCKET not set)   # normal when bucket not configured
wazuh_shipper: starting — bucket=segs-logs-pdax prefix=segs/logs interval=60s
wazuh_shipper: shipped activity_audit 142 bytes → s3://segs-logs-pdax/segs/logs/activity_audit/...
```

**Verify shipping is working:**

```bash
aws logs filter-log-events \
  --log-group-name /segs/dashboard \
  --filter-pattern "wazuh_shipper: shipped" \
  --region ap-southeast-1
```

**Check S3 for recent objects:**

```bash
aws s3 ls s3://YOUR_BUCKET/segs/logs/ --recursive --region ap-southeast-1 | tail -20
```

### Checkpoint file

The shipper maintains byte offsets in `data/wazuh_shipper_offsets.json` (on EFS). This ensures no records are re-shipped or skipped across restarts. If this file is deleted, the shipper re-ships all records from the beginning of each log file — safe (Wazuh deduplicates by timestamp + content) but inefficient.

---

## Common questions

**Q: A phishing email got through. What happened?**

Check the Feed for that message. If SEGS processed it, the finding report will show why it scored below the quarantine threshold. This is a false negative — note the finding types, consider raising weights. If SEGS didn't process it, check whether the recipient mailbox is in `SEG_GMAIL_USERS` and whether the Gmail watch is active.

**Q: A legitimate email is in quarantine.**

Click **Release**. Then check which finding types caused the false positive. If it's a recurring pattern (e.g., a partner domain that looks like a lookalike), add it to the trusted domains list.

**Q: The dashboard shows "No data" after login.**

This usually means the ECS task is unhealthy or the database migration didn't run. Check CloudWatch → `/segs/dashboard` for errors. If the task is running but `data/events.db` is empty, check whether the receiver is healthy and the Gmail watches are registered.

**Q: How do I add a new mailbox to monitor?**

1. Add the mailbox email to `SEG_GMAIL_USERS` in Secrets Manager (comma-separated)
2. Run `bash deploy/update-service.sh` to restart the receiver (picks up new env var)
3. The lifespan hook registers the watch automatically on restart
