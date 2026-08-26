#!/bin/bash
# One-time setup: create (or update) the AWS Secrets Manager secret segs/prod.
#
# Run from the repo root after filling in your real values:
#   AWS_ACCOUNT_ID=123456789012 bash deploy/setup-secrets.sh
#
# The secret stores ALL env vars as key/value pairs in a single JSON object.
# ECS task definitions reference individual keys via:
#   "valueFrom": "arn:...:secret:segs/prod:<KEY>::"
#
# SEGS_GMAIL_CREDENTIALS_JSON stores the contents of credentials.json as a
# single-line JSON string. entrypoint.sh writes it to disk at container start.

set -euo pipefail

AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID:?Set AWS_ACCOUNT_ID}"
AWS_REGION="${AWS_REGION:-ap-southeast-1}"
SECRET_NAME="segs/prod"

# ── Collect values ────────────────────────────────────────────────────────────
# Read from environment, prompting for any that are missing.

prompt() {
    local var="$1" prompt="$2"
    if [ -z "${!var:-}" ]; then
        read -r -p "$prompt: " "$var"
    fi
}

prompt SEG_GMAIL_TOPIC        "GCP Pub/Sub topic (projects/.../topics/...)"
prompt SEG_GMAIL_USERS        "Monitored mailboxes (comma-separated)"
prompt SEG_PUBSUB_TOKEN       "Pub/Sub shared secret token"
prompt SEG_GLM_MODEL_ID       "GLM model ID"
prompt SEG_GLM_API_KEY        "GLM API key (or leave blank if using service account)"
prompt SEG_GLM_PROJECT_ID     "GCP project ID"
prompt SEG_GLM_FALLBACK1_MODEL_ID "GLM fallback 1 model ID"
prompt SEG_GLM_FALLBACK2_MODEL_ID "GLM fallback 2 model ID"
prompt SEG_GLM_FALLBACK2_LOCATION "GLM fallback 2 location"
prompt SEG_GLM_FALLBACK3_MODEL_ID "GLM fallback 3 model ID"
prompt SEG_GLM_FALLBACK3_LOCATION "GLM fallback 3 location"
prompt SEG_VT_API_KEY         "VirusTotal API key"
prompt SEG_ABUSEIPDB_API_KEY  "AbuseIPDB API key"
prompt SEGS_NOTIFY_SMTP_PASS  "SMTP App Password for segs-alerts@pdax.ph"

# credentials.json → single-line JSON string
CREDS_FILE="${CREDENTIALS_JSON_PATH:-credentials.json}"
if [ -f "$CREDS_FILE" ]; then
    SEGS_GMAIL_CREDENTIALS_JSON="$(python3 -c "import json,sys; print(json.dumps(json.load(open('$CREDS_FILE'))))")"
else
    echo "WARNING: $CREDS_FILE not found. Set SEGS_GMAIL_CREDENTIALS_JSON manually." >&2
    SEGS_GMAIL_CREDENTIALS_JSON=""
fi

# ── Build secret JSON ─────────────────────────────────────────────────────────
SECRET_VALUE=$(python3 - <<PYEOF
import json, os
keys = [
    "SEG_GMAIL_TOPIC", "SEG_GMAIL_USERS", "SEG_PUBSUB_TOKEN",
    "SEG_GLM_MODEL_ID", "SEG_GLM_API_KEY", "SEG_GLM_PROJECT_ID",
    "SEG_GLM_FALLBACK1_MODEL_ID",
    "SEG_GLM_FALLBACK2_MODEL_ID", "SEG_GLM_FALLBACK2_LOCATION",
    "SEG_GLM_FALLBACK3_MODEL_ID", "SEG_GLM_FALLBACK3_LOCATION",
    "SEG_VT_API_KEY", "SEG_ABUSEIPDB_API_KEY",
    "SEGS_NOTIFY_SMTP_PASS", "SEGS_GMAIL_CREDENTIALS_JSON",
]
print(json.dumps({k: os.environ.get(k, "") for k in keys}))
PYEOF
)

# ── Create or update ──────────────────────────────────────────────────────────
if aws secretsmanager describe-secret \
     --region "$AWS_REGION" \
     --secret-id "$SECRET_NAME" \
     --query 'Name' --output text 2>/dev/null | grep -q "$SECRET_NAME"; then

    echo "==> Updating existing secret $SECRET_NAME..."
    aws secretsmanager put-secret-value \
      --region "$AWS_REGION" \
      --secret-id "$SECRET_NAME" \
      --secret-string "$SECRET_VALUE"
else
    echo "==> Creating secret $SECRET_NAME..."
    aws secretsmanager create-secret \
      --region "$AWS_REGION" \
      --name "$SECRET_NAME" \
      --description "SEGS production environment variables" \
      --secret-string "$SECRET_VALUE"
fi

echo "==> Secret $SECRET_NAME updated successfully."
echo "    ARN: $(aws secretsmanager describe-secret --region $AWS_REGION --secret-id $SECRET_NAME --query ARN --output text)"
