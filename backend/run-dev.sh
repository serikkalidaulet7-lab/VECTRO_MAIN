#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

export JWT_PRIVATE_KEY="$(cat .secrets/jwt-private.pem)"
export JWT_PUBLIC_KEY="$(cat .secrets/jwt-public.pem)"
export DEBUG=false

exec uv run uvicorn app.main:app \
  --reload \
  --host 127.0.0.1 \
  --port 8000
