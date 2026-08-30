#!/bin/sh
# Write credentials.json from Secrets Manager, then start a single uvicorn worker.
#
# --workers 1 is required: sender-profile ingest, inconclusive LLM retry, and
# the Gmail poll loop are in-process threads. Extra uvicorn workers would
# duplicate those loops and split the LLM queue.
#
# Usage:
#   sh /opt/segs/entrypoint.sh backend.api.main:app 8765
#   sh /opt/segs/entrypoint.sh workers.receiver:app 8766

set -eu

APP_MODULE="${1:-backend.api.main:app}"
PORT="${2:-8765}"

# shellcheck source=/dev/null
. /opt/segs/tls-env.sh
segs_write_tls

if [ -n "${SEGS_GMAIL_CREDENTIALS_JSON:-}" ]; then
    CREDS_PATH="${SEG_GMAIL_CREDENTIALS:-/opt/segs/credentials.json}"
    (umask 177 && printf '%s' "$SEGS_GMAIL_CREDENTIALS_JSON" > "$CREDS_PATH")
    echo "[entrypoint] credentials.json written to $CREDS_PATH (mode 600)" >&2
fi

set -- python -m uvicorn "$APP_MODULE" \
    --host 0.0.0.0 \
    --port "$PORT" \
    --workers 1 \
    --proxy-headers \
    --forwarded-allow-ips='*'

if [ -n "${SEG_TLS_CERT_PATH:-}" ] && [ -n "${SEG_TLS_KEY_PATH:-}" ]; then
    echo "[entrypoint] TLS enabled (${SEG_TLS_CERT_PATH})" >&2
    set -- "$@" --ssl-certfile "$SEG_TLS_CERT_PATH" --ssl-keyfile "$SEG_TLS_KEY_PATH"
fi

exec "$@"
