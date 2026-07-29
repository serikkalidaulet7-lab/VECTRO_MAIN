#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
PRIVATE_KEY="$BACKEND_DIR/.secrets/jwt-private.pem"
PUBLIC_KEY="$BACKEND_DIR/.secrets/jwt-public.pem"

if [[ ! -r "$PRIVATE_KEY" || ! -r "$PUBLIC_KEY" ]]; then
    echo "Development JWT keys are missing. Run ./scripts/generate-dev-jwt-keys.sh first." >&2
    exit 1
fi

case "${DEBUG:-false}" in
    true|false|True|False|TRUE|FALSE|1|0|yes|no|on|off) ;;
    *)
        echo "DEBUG must be a valid boolean value." >&2
        exit 1
        ;;
esac

export JWT_PRIVATE_KEY="$(<"$PRIVATE_KEY")"
export JWT_PUBLIC_KEY="$(<"$PUBLIC_KEY")"
export DEBUG="${DEBUG:-false}"
export PORT="${PORT:-8000}"

cd "$BACKEND_DIR"
exec uv run uvicorn app.main:app --reload --host 127.0.0.1 --port "$PORT"
