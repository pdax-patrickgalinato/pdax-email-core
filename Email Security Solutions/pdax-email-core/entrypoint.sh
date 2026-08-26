#!/bin/sh
# Container entrypoint — writes credentials.json from env var before starting uvicorn.
#
# In ECS, store the contents of credentials.json as a Secrets Manager secret value
# and inject it as SEGS_GMAIL_CREDENTIALS_JSON. This script writes it to the path
# expected by SEG_GMAIL_CREDENTIALS so google-auth can read it.
#
# Usage in task definition CMD:
#   ["sh", "/opt/segs/entrypoint.sh", "server.main:app", "8765"]
#   ["sh", "/opt/segs/entrypoint.sh", "gateway.gmail_receiver:app", "8766"]

set -e

APP_MODULE="${1:-server.main:app}"
PORT="${2:-8765}"

# Write GCP service-account credentials from env var (set via Secrets Manager in ECS)
if [ -n "$SEGS_GMAIL_CREDENTIALS_JSON" ]; then
    CREDS_PATH="${SEG_GMAIL_CREDENTIALS:-/opt/segs/credentials.json}"
    printf '%s' "$SEGS_GMAIL_CREDENTIALS_JSON" > "$CREDS_PATH"
    chmod 600 "$CREDS_PATH"
    echo "[entrypoint] credentials.json written to $CREDS_PATH" >&2
fi

exec python -m uvicorn "$APP_MODULE" \
    --host 0.0.0.0 \
    --port "$PORT" \
    --workers 1
