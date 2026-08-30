#!/usr/bin/env bash
# Write operator key/value pairs into the SEGS app Secrets Manager secret.
# Reads from the environment (or a sourced .env). Never prints values.
#
# Usage:
#   set -a && source ../.env && set +a
#   bash infra/scripts/put-secrets.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
INFRA="$ROOT/infra"
REGION="${AWS_REGION:-ap-southeast-1}"

cd "$INFRA"
SECRET_ARN="$(terraform output -raw secrets_arn)"

CREDS_FILE="${CREDENTIALS_JSON_PATH:-$ROOT/credentials.json}"
if [ -f "$CREDS_FILE" ] && [ -z "${SEGS_GMAIL_CREDENTIALS_JSON:-}" ]; then
  SEGS_GMAIL_CREDENTIALS_JSON="$(python3 -c "import json,sys; print(json.dumps(json.load(open(sys.argv[1]))))" "$CREDS_FILE")"
  export SEGS_GMAIL_CREDENTIALS_JSON
fi

SECRET_VALUE="$(python3 - <<'PY'
import json, os
keys = [
    "SEG_GMAIL_USERS",
    "SEG_GMAIL_DOMAIN",
    "SEG_ENFORCE",
    "SEG_CONTENT_PROVIDER",
    "SEG_INTEL_CLIENT",
    "SEG_GLM_MODEL_ID",
    "SEG_GLM_API_KEY",
    "SEG_GLM_PROJECT_ID",
    "SEG_GLM_FALLBACK1_MODEL_ID",
    "SEG_GLM_FALLBACK2_MODEL_ID",
    "SEG_GLM_FALLBACK2_LOCATION",
    "SEG_GLM_FALLBACK3_MODEL_ID",
    "SEG_GLM_FALLBACK3_LOCATION",
    "SEG_VT_API_KEY",
    "SEG_ABUSEIPDB_API_KEY",
    "SEGS_NOTIFY_SMTP_PASS",
    "SEGS_GMAIL_CREDENTIALS_JSON",
]
missing = [k for k in ("SEG_GMAIL_USERS", "SEGS_GMAIL_CREDENTIALS_JSON") if not os.environ.get(k)]
if missing:
    raise SystemExit("missing required env: " + ", ".join(missing))
print(json.dumps({k: os.environ.get(k, "") for k in keys}))
PY
)"

aws secretsmanager put-secret-value \
  --region "$REGION" \
  --secret-id "$SECRET_ARN" \
  --secret-string "$SECRET_VALUE" \
  >/dev/null

echo "Updated secret ${SECRET_ARN}"
