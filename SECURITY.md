# Security Policy

## Supported Versions

SEGS is an internal security tool maintained by the PDAX Security Operations team. Only the latest version on the `main` branch is actively supported.

## Reporting a Vulnerability

If you discover a security vulnerability in SEGS, **do not open a public GitHub issue.**

Report it privately:

- **Email:** security@pdax.ph
- **Subject:** `[SEGS Security] <brief description>`
- **PGP:** Contact the security team for a PGP public key if your report contains sensitive details.

### What to include

- Description of the vulnerability and affected component
- Steps to reproduce (or proof-of-concept if available)
- Potential impact assessment
- Any suggested mitigations

### Response timeline

| Milestone | Target |
|-----------|--------|
| Acknowledgement | 2 business days |
| Initial severity assessment | 5 business days |
| Fix or mitigation | Depends on severity (Critical: 7 days, High: 14 days, Medium/Low: 30 days) |

## Scope

### In scope

- The SEGS dashboard application (`backend/api/`)
- The Gmail receiver service (`workers/`)
- The email analysis pipeline (`workers/pipeline/`)
- Deployment scripts and container configuration (`deploy/`, including `deploy/docker/` and `deploy/ecs/`)
- Authentication and session management (`backend/api/auth_store.py`, `backend/api/security.py`)

### Out of scope

- Third-party services integrated with SEGS (Gmail API, VirusTotal, AbuseIPDB, GLM/Vertex AI)
- The underlying host OS, AWS infrastructure, or network configuration (report to the PDAX infrastructure team)
- Social engineering attacks targeting PDAX employees
- Denial-of-service via resource exhaustion at the network level

## Security Design Principles

SEGS is built on defense-in-depth principles:

1. **Least privilege** — each component only accesses what it needs
2. **Fail-secure** — pipeline errors default to holding (not releasing) suspicious mail
3. **Zero trust** — every email is treated as potentially malicious regardless of sender reputation
4. **Non-repudiation** — all analyst actions are logged in the activity audit trail
5. **Data minimization** — PII (email content, sender addresses) is stored only in the spool and never in application logs

## Known Limitations

- The Content-Security-Policy includes `'unsafe-inline'` for `script-src` due to the dashboard's use of inline `<script>` blocks. A nonce-based CSP refactor is planned.
- The in-memory rate limiter resets on container restart. This is a known limitation for a VPN-only internal tool; a Redis-backed limiter would be needed for a public-facing deployment.
