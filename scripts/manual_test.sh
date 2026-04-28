#!/usr/bin/env bash

set -euo pipefail

APP_URL="${APP_URL:-http://app.localhost}"
VAULTWARDEN_URL="${VAULTWARDEN_URL:-http://vaultwarden.localhost}"

echo "=== SSO Stand Manual Smoke Test ==="
echo "App: $APP_URL"
echo "Vaultwarden: $VAULTWARDEN_URL"
echo ""

echo "1. Checking profile selector"
profiles_page="$(curl -fsS "$APP_URL/")"
for profile in profile-a profile-b profile-c; do
  if echo "$profiles_page" | grep -q "data-profile=\"$profile\""; then
    echo "[ok] $profile is listed"
  else
    echo "✗ $profile is missing"
    exit 1
  fi
done

echo ""
echo "2. Checking anonymous protected redirect"
protected_status="$(curl -s -o /dev/null -w "%{http_code}" "$APP_URL/protected")"
if [[ "$protected_status" == "302" ]]; then
  echo "[ok] /protected redirects anonymous users"
else
  echo "✗ /protected expected 302, got $protected_status"
  exit 1
fi

echo ""
echo "3. Checking Vaultwarden availability"
vaultwarden_status="$(curl -s -o /dev/null -w "%{http_code}" "$VAULTWARDEN_URL/alive" || true)"
if [[ "$vaultwarden_status" == "200" ]]; then
  echo "[ok] Vaultwarden is alive"
else
  echo "[warn] Vaultwarden /alive returned $vaultwarden_status"
fi

echo ""
echo "Browser checks:"
echo "- Profile A: choose Profile A, log in to Keycloak with testuser1/password123."
echo "- Profile B: choose Profile B and use a passkey/WebAuthn authenticator."
echo "- Profile C: save testuser1/password123 in Vaultwarden/Bitwarden and fill the app login form."
