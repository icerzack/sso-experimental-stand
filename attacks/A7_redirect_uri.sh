#!/usr/bin/env bash
# A7 — Redirect URI Manipulation (Open Redirect in OAuth2)
# OWASP ASVS v4.2 § 3.5.2 / RFC 6749 §10.6
# MITRE ATT&CK T1078
#
# Sends an authorization request to Keycloak with an attacker-controlled
# redirect_uri. A misconfigured realm (redirectUris=["*"]) will redirect the
# user's browser — and the authorization code — to the attacker's server.
#
# Usage:
#   bash A7_redirect_uri.sh <keycloak_base_url> [realm] [client_id]
#
# Examples:
#   bash A7_redirect_uri.sh http://keycloak.local:8080 profile-a-vulnerable sso-test-app
#   bash A7_redirect_uri.sh http://keycloak.local:8080 profile-a-hardened   sso-test-app
#
# Result:
#   VULNERABLE — invalid redirect_uri is accepted (redirects or login page shown)
#   PROTECTED  — Keycloak rejects invalid redirect_uri before auth

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

KC_URL="${1:?Usage: $0 <keycloak_base_url> [realm] [client_id]}"
REALM="${2:-profile-a-vulnerable}"
CLIENT_ID="${3:-sso-test-app}"
EVIL_URI="https://evil.example.com/steal"

AUTH_ENDPOINT="${KC_URL%/}/realms/${REALM}/protocol/openid-connect/auth"
STATE="teststate123"

echo "[A7] Redirect URI manipulation"
echo "     Keycloak: $KC_URL"
echo "     Realm:    $REALM"
echo "     Client:   $CLIENT_ID"
echo "     Evil URI: $EVIL_URI"
echo

QUERY="client_id=${CLIENT_ID}&response_type=code&scope=openid&redirect_uri=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$EVIL_URI")&state=${STATE}"
FULL_URL="${AUTH_ENDPOINT}?${QUERY}"

echo "  [1] Auth URL:"
echo "      ${FULL_URL:0:120}…"
echo

# Follow redirects and capture the final Location header
RESPONSE=$(rcurl -si --max-redirs 5 "$FULL_URL" 2>/dev/null || true)
LOCATION=$(echo "$RESPONSE" | grep -i "^location:" | tail -1 || true)
HTTP_STATUS=$(echo "$RESPONSE" | head -1 | awk '{print $2}' || true)

echo "  [2] Response status: $HTTP_STATUS"
if [[ -n "$LOCATION" ]]; then
  echo "  [3] Location header: ${LOCATION:0:120}"
fi

ERROR_PARAM=$(echo "$LOCATION" | grep -o "error=[^&]*" || true)
BODY=$(echo "$RESPONSE" | sed -n '/^\r$/,$p')

echo

if echo "$LOCATION" | grep -q "evil.example.com"; then
  echo "VULNERABLE — Keycloak redirected to the attacker's URI"
elif [[ -n "$ERROR_PARAM" ]] || echo "$BODY" | grep -qi "invalid_redirect_uri"; then
  echo "PROTECTED  — Keycloak rejected the redirect ($ERROR_PARAM)"
elif [[ "$HTTP_STATUS" == "200" || "$HTTP_STATUS" == "302" ]]; then
  echo "VULNERABLE — invalid redirect_uri was accepted (no invalid_redirect_uri error)"
else
  echo "PROTECTED  — invalid redirect_uri appears rejected (HTTP $HTTP_STATUS)"
fi
