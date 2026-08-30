# SEGS — JumpCloud SSO Integration Guide

> **Status**: Planned future implementation. The platform is SSO-ready — the middleware hook exists and activates with a single environment variable. No code changes required when you're ready to enable it.

---

## Overview

SEGS uses **AWS ALB OIDC authentication** as the SSO layer. When enabled, the ALB validates every user's JumpCloud session before the request ever reaches the SEGS container. SEGS itself sees a trusted header (`x-amzn-oidc-identity`) injected by the ALB.

This means:
- Only users in your JumpCloud org can reach the dashboard
- JumpCloud controls access (add/remove users, enforce MFA, device trust)
- SEGS's own login is a second layer on top for role-based access (Admin / Analyst / Viewer)

```
Browser → ALB (JumpCloud OIDC check) → SEGS container (SEGS session check)
```

---

## How the SSO switch works

The `SSOMiddleware` in `server/security.py` reads `SEG_SSO_PROVIDER`:

| Value | Behavior |
|-------|---------|
| _(empty, default)_ | No-op — all traffic falls through to SEGS's own auth |
| `alb_oidc` | Requires `x-amzn-oidc-identity` header; rejects requests that bypass the ALB |

**To enable SSO**: set `SEG_SSO_PROVIDER=alb_oidc` in Secrets Manager and redeploy. No code change.

---

## Step-by-step activation

### Step 1 — Create a JumpCloud SSO Application

1. JumpCloud Admin Console → SSO Applications → Add New Application
2. Choose **Custom OIDC Application**
3. Settings:
   - **Display name**: `SEGS Dashboard`
   - **Redirect URIs**: `https://segs.pdax.ph/oauth2/idpresponse`
   - **Client authentication**: Client secret
   - **Grant type**: Authorization code
4. Copy the **Client ID** and **Client Secret**
5. Copy the **Discovery URL**: `https://oauth.id.jumpcloud.com/.well-known/openid-configuration`
6. Assign the application to the SOC team group in JumpCloud

### Step 2 — Configure ALB OIDC authentication

On the dashboard ALB (internal or internet-facing), modify the HTTPS listener:

```bash
# Add OIDC action to the listener (replace REPLACE_* values)
aws elbv2 modify-listener \
  --listener-arn arn:aws:elasticloadbalancing:ap-southeast-1:ACCOUNT:listener/... \
  --default-actions '[
    {
      "Type": "authenticate-oidc",
      "Order": 1,
      "AuthenticateOidcConfig": {
        "Issuer": "https://oauth.id.jumpcloud.com",
        "AuthorizationEndpoint": "https://oauth.id.jumpcloud.com/oauth2/v1/authorize",
        "TokenEndpoint": "https://oauth.id.jumpcloud.com/oauth2/v1/token",
        "UserInfoEndpoint": "https://oauth.id.jumpcloud.com/oauth2/v1/userinfo",
        "ClientId": "REPLACE_JUMPCLOUD_CLIENT_ID",
        "ClientSecret": "REPLACE_JUMPCLOUD_CLIENT_SECRET",
        "SessionCookieName": "AWSELBAuthSessionCookie",
        "SessionTimeout": 86400,
        "Scope": "openid email profile",
        "OnUnauthenticatedRequest": "authenticate"
      }
    },
    {
      "Type": "forward",
      "Order": 2,
      "TargetGroupArn": "arn:aws:elasticloadbalancing:...:targetgroup/segs-dashboard/..."
    }
  ]'
```

Or configure via AWS Console:
- EC2 → Load Balancers → segs-dashboard-alb → Listeners → HTTPS:443 → Edit
- Default action: **Authenticate** → OpenID Connect
- Fill in JumpCloud OIDC endpoints and client credentials
- After authenticate action: **Forward** to segs-dashboard target group

### Step 3 — Store JumpCloud credentials in Secrets Manager

Add these keys to `segs/prod`:

```bash
aws secretsmanager put-secret-value \
  --secret-id segs/prod \
  --secret-string "$(aws secretsmanager get-secret-value \
    --secret-id segs/prod --query SecretString --output text \
    | python3 -c "
import json, sys
d = json.load(sys.stdin)
d['SEG_SSO_PROVIDER'] = 'alb_oidc'
d['SEG_OIDC_CLIENT_ID'] = 'REPLACE_CLIENT_ID'
d['SEG_OIDC_CLIENT_SECRET'] = 'REPLACE_CLIENT_SECRET'
d['SEG_OIDC_ISSUER'] = 'https://oauth.id.jumpcloud.com'
print(json.dumps(d))
")"
```

### Step 4 — Enable the SSO middleware

```bash
# Update secret: set SEG_SSO_PROVIDER=alb_oidc (already done in Step 3)
# Force redeploy to pick up the new value:
bash deploy/update-service.sh
```

### Step 5 — Verify

1. Open `https://segs.pdax.ph` in a browser that is **not** logged into JumpCloud
2. Should redirect to JumpCloud login page
3. Log in with a JumpCloud account that has the SEGS SSO app assigned
4. Should redirect back to `segs.pdax.ph` and show the SEGS login screen
5. Log in with SEGS credentials → dashboard loads

---

## Access control model (after SSO)

```
Layer 1 — JumpCloud SSO (ALB)
  Who can reach the app at all:
  → Only users in the JumpCloud "SEGS SOC" group
  → JumpCloud enforces MFA, device trust, location policies

Layer 2 — SEGS session auth (app)
  What users can do inside the app:
  → Admin:    full access (users, settings, policy, all actions)
  → Analyst:  view feed, release/block quarantine
  → Viewer:   read-only feed
```

---

## Security group change after SSO

Once SSO is live, you can optionally restrict the dashboard ALB security group
to **only allow traffic from the ALB itself** (loopback isn't relevant — restrict
to your office IP or keep it open since ALB OIDC handles auth). If you previously
opened port 443 to `0.0.0.0/0` for initial setup, that's still fine — the OIDC
layer prevents any unauthenticated access.

---

## JumpCloud SSO environment variables

| Variable | Description |
|----------|-------------|
| `SEG_SSO_PROVIDER` | `alb_oidc` to enable; empty to disable |
| `SEG_OIDC_CLIENT_ID` | JumpCloud OIDC app client ID (stored in Secrets Manager; used only for documentation — the ALB uses it directly) |
| `SEG_OIDC_CLIENT_SECRET` | JumpCloud OIDC app client secret (same note) |
| `SEG_OIDC_ISSUER` | `https://oauth.id.jumpcloud.com` |

---

## Rollback

To disable SSO (e.g., during troubleshooting):

```bash
# 1. Set SEG_SSO_PROVIDER back to empty in Secrets Manager
# 2. Remove the OIDC action from the ALB listener (revert to forward-only)
# 3. Redeploy: bash deploy/update-service.sh
```
