#!/bin/bash
# Launch the SEGS dashboard from this directory (repo root).
cd "$(dirname "$0")"

if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi

if [ ! -f web-console/dist/index.html ]; then
  echo "web-console/dist is missing. Build the React console first:" >&2
  echo "  (cd web-console && npm install && npm run build)" >&2
  echo "API routes still start; GET / will return a JSON hint until dist exists." >&2
fi

echo "SEGS dashboard: http://localhost:8765"
exec .venv/bin/uvicorn backend.api.main:app --host 127.0.0.1 --reload --port 8765 \
    --no-server-header
