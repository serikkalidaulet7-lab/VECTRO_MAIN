#!/usr/bin/env sh
set -eu

load_secret_file() {
    variable_name=$1
    file_variable_name=$2
    eval "current_value=\${$variable_name:-}"
    eval "secret_file=\${$file_variable_name:-}"

    if [ -z "$current_value" ] && [ -n "$secret_file" ]; then
        if [ ! -r "$secret_file" ]; then
            echo "Configured JWT secret file is unavailable." >&2
            exit 1
        fi
        export "$variable_name=$(cat "$secret_file")"
    fi
}

load_secret_file JWT_PRIVATE_KEY JWT_PRIVATE_KEY_FILE
load_secret_file JWT_PUBLIC_KEY JWT_PUBLIC_KEY_FILE

if [ "${REQUIRE_JWT_KEYS:-false}" = "true" ] && { [ -z "${JWT_PRIVATE_KEY:-}" ] || [ -z "${JWT_PUBLIC_KEY:-}" ]; }; then
    echo "JWT signing and verification keys must be configured." >&2
    exit 1
fi

exec "$@"
