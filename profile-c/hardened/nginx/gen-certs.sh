#!/bin/sh
# Generate a self-signed TLS certificate for app-c-h.local.
# Run once before starting the hardened Profile C stack:
#   cd profile-c/hardened/nginx && sh gen-certs.sh
set -e
DIR="$(cd "$(dirname "$0")" && pwd)/certs"
mkdir -p "$DIR"
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout "$DIR/key.pem" \
  -out    "$DIR/cert.pem" \
  -subj   "/CN=app-c-h.local" \
  -addext "subjectAltName=DNS:app-c-h.local"
echo "Certificates written to $DIR"
echo "To trust the cert on macOS: sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain $DIR/cert.pem"
