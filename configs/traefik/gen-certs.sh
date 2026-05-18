#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CERTS_DIR="$PROJECT_DIR/certs"

mkdir -p "$CERTS_DIR"

if ! command -v mkcert &>/dev/null; then
    echo "mkcert not found. Install: brew install mkcert (macOS) or apt install mkcert (Linux)"
    exit 1
fi

mkcert -install
mkcert -key-file "$CERTS_DIR/sso-lab.local.key" \
        -cert-file "$CERTS_DIR/sso-lab.local.crt" \
        "*.sso-lab.local" sso-lab.local localhost

echo "Certificates generated in $CERTS_DIR/"
