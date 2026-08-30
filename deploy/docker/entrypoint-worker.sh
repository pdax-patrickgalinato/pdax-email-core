#!/bin/sh
# Write credentials.json from Secrets Manager, then run one worker process.
#
# Usage:
#   sh /opt/segs/entrypoint-worker.sh identity
#   SEG_WORKER=gmail_poll sh /opt/segs/entrypoint-worker.sh

set -eu

# Prefer SEG_WORKER. Fargate uses the image CMD as $1 when the task
# definition omits `command`; the worker image default is `static`, which
# would otherwise start every split service as the static worker.
WORKER="${SEG_WORKER:-${1:-}}"
if [ -z "$WORKER" ]; then
    echo "usage: entrypoint-worker.sh <worker-name>" >&2
    echo "  or set SEG_WORKER" >&2
    exit 2
fi

# shellcheck source=/dev/null
. /opt/segs/tls-env.sh
segs_write_tls

if [ -n "${SEGS_GMAIL_CREDENTIALS_JSON:-}" ]; then
    CREDS_PATH="${SEG_GMAIL_CREDENTIALS:-/opt/segs/credentials.json}"
    (umask 177 && printf '%s' "$SEGS_GMAIL_CREDENTIALS_JSON" > "$CREDS_PATH")
    echo "[entrypoint] credentials.json written to $CREDS_PATH (mode 600)" >&2
fi

export SEG_WORKER="$WORKER"
exec python -m workers "$WORKER"
