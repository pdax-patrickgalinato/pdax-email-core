#!/bin/bash
# First-run admin account creation for SEGS.
#
# Run once after the ECS service is stable and BEFORE anyone visits the dashboard.
# The setup endpoint permanently closes after the first account is created.
#
# Usage:
#   SEGS_URL=https://segs.pdax.ph \
#   SEGS_ADMIN_USER=admin \
#   SEGS_ADMIN_PASS='YourPass1!' \
#   bash deploy/bootstrap_admin.sh
#
# Password rules (enforced by the app):
#   - At least 8 characters
#   - At least one uppercase letter (A-Z)
#   - At least one lowercase letter (a-z)
#   - At least one number (0-9)
#   - At least one special character (!@#$%^&* etc.)
#
# After this runs:
#   1. Log in at $SEGS_URL with the credentials above
#   2. Add analyst/viewer accounts via Settings → Users
#   3. Remove SEGS_ADMIN_PASS from any shell history or environment

set -euo pipefail

SEGS_URL="${SEGS_URL:?Set SEGS_URL — e.g. https://segs.pdax.ph or http://127.0.0.1:8765}"
SEGS_ADMIN_USER="${SEGS_ADMIN_USER:?Set SEGS_ADMIN_USER — the first admin username}"
SEGS_ADMIN_PASS="${SEGS_ADMIN_PASS:?Set SEGS_ADMIN_PASS — must meet complexity rules}"

echo "==> Checking SEGS setup status at $SEGS_URL ..."

STATUS_JSON=$(curl -sf --max-time 10 "$SEGS_URL/api/auth/setup/status" 2>/dev/null || echo '{"error":true}')
NEEDS_SETUP=$(echo "$STATUS_JSON" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('needs_setup','error'))" 2>/dev/null || echo "error")

if [ "$NEEDS_SETUP" = "False" ]; then
    echo ""
    echo "ERROR: An admin account already exists — the setup endpoint is closed."
    echo "       Manage accounts at: $SEGS_URL (Settings → Users)"
    exit 1
fi

if [ "$NEEDS_SETUP" = "error" ]; then
    echo ""
    echo "ERROR: Could not reach $SEGS_URL/api/auth/setup/status"
    echo "       Is the server running and reachable?"
    echo "       Raw response: $STATUS_JSON"
    exit 1
fi

echo "==> Creating admin account '$SEGS_ADMIN_USER' ..."

# Build JSON body using Python to ensure correct quoting and escaping.
# The old approach used json.dumps then tr -d '"' which stripped the required
# surrounding quotes, producing syntactically invalid JSON for most passwords.
BODY=$(python3 -c "
import json, sys
username = sys.argv[1]
password = sys.argv[2]
print(json.dumps({'username': username, 'password': password}))
" "$SEGS_ADMIN_USER" "$SEGS_ADMIN_PASS")

# Write curl output to a mode-600 temp file to avoid world-readable /tmp exposure.
BOOTSTRAP_TMP=$(mktemp)
chmod 600 "$BOOTSTRAP_TMP"

HTTP_CODE=$(curl -s -o "$BOOTSTRAP_TMP" -w "%{http_code}" \
    --max-time 15 \
    -X POST "$SEGS_URL/api/auth/setup" \
    -H "Content-Type: application/json" \
    -d "$BODY" \
    2>/dev/null)

if [ "$HTTP_CODE" = "200" ]; then
    rm -f "$BOOTSTRAP_TMP"
    echo ""
    echo "Admin account created successfully."
    echo ""
    echo "  Dashboard: $SEGS_URL"
    echo "  Username:  $SEGS_ADMIN_USER"
    echo ""
    echo "Next steps:"
    echo "  1. Log in and verify the dashboard loads correctly"
    echo "  2. Add SOC analyst accounts: Settings -> Users -> Add User"
    echo "  3. Register Gmail watches: Settings -> Gmail Watches -> Register"
    echo "  4. Start in shadow mode — review the Feed for 2 weeks before enabling quarantine"
    echo ""
    echo "Security note: clear SEGS_ADMIN_PASS from your shell history:"
    echo "  history -c   (bash)   OR   history -p   (zsh)"
else
    echo ""
    echo "ERROR: Setup request failed (HTTP $HTTP_CODE)"
    echo "Response:"
    cat "$BOOTSTRAP_TMP" 2>/dev/null || true
    rm -f "$BOOTSTRAP_TMP"
    echo ""
    echo "Common causes:"
    echo "  - Password does not meet complexity rules (uppercase, lowercase, number, special char)"
    echo "  - Server not yet ready — wait 30 seconds and retry"
    exit 1
fi
