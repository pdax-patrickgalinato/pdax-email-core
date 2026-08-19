#!/bin/bash
cd "/Users/ronald.galinato/Documents/Cybersecurity-Pat/Email Security Solutions/pdax-email-core"

# Load API keys and feature flags from .env if it exists
if [ -f .env ]; then
  source .env
fi

exec .venv/bin/uvicorn server.main:app --reload --port 8765
