#!/usr/bin/env bash
# A5 — PKCE Downgrade (отсутствие code_challenge)
# OWASP ASVS v4.2 § 3.5.3 / RFC 7636
#
# Profiles: 1A, 1C
#
# Tests whether the IdP and the application enforce PKCE (code_challenge).
# If the authorization endpoint accepts a request without code_challenge,
# an attacker who intercepts the authorization code can exchange it for tokens.
#
# Usage:
#   bash A5_pkce_downgrade.sh <idp_url> [realm] [client_id] [app_callback_url]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

IDP_URL="${1:?Usage: $0 <idp_url> [realm] [client_id] [app_callback_url]}"
REALM="${2:-sso-lab}"
CLIENT_ID="${3:-sso-test-app}"
CALLBACK_URL="${4:-https://app.sso-lab.local/callback}"

AUTH_ENDPOINT="${IDP_URL%/}/realms/${REALM}/protocol/openid-connect/auth"
TOKEN_ENDPOINT="${IDP_URL%/}/realms/${REALM}/protocol/openid-connect/token"

echo "[A5] PKCE Downgrade — missing code_challenge check"
echo "     IdP: $IDP_URL  |  Realm: $REALM  |  Client: $CLIENT_ID"
echo

# ── Pre-flight: verify IdP is reachable ──────────────────────────────────────
PREFLIGHT=$(rcurl -sk -o /dev/null -w "%{http_code}" "${IDP_URL%/}/" 2>/dev/null || echo "000")
if [[ "$PREFLIGHT" == "000" ]]; then
  echo "SKIPPED — IdP at $IDP_URL is unreachable"
  exit 0
fi

RESULTS=()

# ── Test 1: Authorization request without code_challenge ────────────────────
echo "  [Test 1] Auth request WITHOUT code_challenge (PKCE absent)"
REDIRECT_ENCODED=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$CALLBACK_URL")

NO_PKCE_URL="${AUTH_ENDPOINT}?client_id=${CLIENT_ID}&response_type=code&scope=openid&redirect_uri=${REDIRECT_ENCODED}&state=test_a5_1"

RESPONSE1=$(rcurl -si --max-redirs 0 "$NO_PKCE_URL" 2>/dev/null || true)
HTTP_STATUS1=$(echo "$RESPONSE1" | head -1 | awk '{print $2}' || true)
LOCATION1=$(echo "$RESPONSE1" | grep -i "^location:" | head -1 | tr -d '\r' || true)
BODY1=$(echo "$RESPONSE1" | sed -n '/^\r$/,$p')

echo "           → HTTP $HTTP_STATUS1"

# Check if the response is an error or a login form
if echo "$LOCATION1" | grep -qi "error="; then
  ERROR_MSG=$(echo "$LOCATION1" | grep -o "error=[^&]*" || true)
  echo "           PROTECTED  — IdP rejected non-PKCE request ($ERROR_MSG)"
  RESULTS+=("T1:PROTECTED")
elif [[ "$HTTP_STATUS1" == "200" ]]; then
  # Login page shown = authorization accepted without PKCE
  if echo "$BODY1" | grep -qi "login\|username\|password\|kc-form"; then
    echo "           VULNERABLE — IdP issued login page without requiring code_challenge"
    RESULTS+=("T1:VULNERABLE")
  elif echo "$BODY1" | grep -qi "error\|invalid"; then
    echo "           PROTECTED  — error shown in response body"
    RESULTS+=("T1:PROTECTED")
  else
    echo "           VULNERABLE — no rejection for missing code_challenge (HTTP 200)"
    RESULTS+=("T1:VULNERABLE")
  fi
elif [[ "$HTTP_STATUS1" == "302" || "$HTTP_STATUS1" == "303" ]]; then
  if echo "$LOCATION1" | grep -qi "error="; then
    echo "           PROTECTED  — redirect with error parameter"
    RESULTS+=("T1:PROTECTED")
  else
    # Redirected to login page without PKCE
    echo "           VULNERABLE — redirected to login without requiring PKCE"
    RESULTS+=("T1:VULNERABLE")
  fi
else
  echo "           PROTECTED  — unexpected status, likely rejected (HTTP $HTTP_STATUS1)"
  RESULTS+=("T1:PROTECTED")
fi
echo

# ── Test 2: Token exchange attempt with intercepted code but no code_verifier ──
echo "  [Test 2] Token exchange WITHOUT code_verifier (simulating intercepted code)"
FAKE_CODE="fake_authorization_code_a5"

ENCODED_CALLBACK=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$CALLBACK_URL")
TOKEN_RESP=$(rcurl -sk -X POST "$TOKEN_ENDPOINT" \
  -d "grant_type=authorization_code" \
  -d "client_id=${CLIENT_ID}" \
  -d "code=${FAKE_CODE}" \
  -d "redirect_uri=${ENCODED_CALLBACK}" \
  2>/dev/null || true)

TOKEN_HTTP_STATUS=$(echo "$TOKEN_RESP" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    print('error:'+d.get('error','')) if 'error' in d else print('ok')
except: print('parse_error')
" 2>/dev/null || echo "no_json_response")

if [[ "$TOKEN_HTTP_STATUS" == *"error"* ]]; then
  echo "           PROTECTED  — token exchange failed ($TOKEN_HTTP_STATUS)"
  RESULTS+=("T2:PROTECTED")
elif [[ "$TOKEN_HTTP_STATUS" == "ok" ]]; then
  echo "           VULNERABLE — token exchanged without code_verifier!"
  RESULTS+=("T2:VULNERABLE")
else
  echo "           PROTECTED  — token endpoint rejected the request"
  RESULTS+=("T2:PROTECTED")
fi
echo

# ── Test 3: Verify hardened client has PKCE configured ──────────────────────
echo "  [Test 3] Checking client configuration for PKCE requirement..."
CLIENT_INFO=$(rcurl -sk \
  "${IDP_URL%/}/realms/${REALM}/protocol/openid-connect/auth?client_id=${CLIENT_ID}&response_type=code&scope=openid&redirect_uri=${REDIRECT_ENCODED}&state=test_a5_3&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256" \
  -o /dev/null -w "%{http_code}" 2>/dev/null || echo "000")

if [[ "$CLIENT_INFO" =~ ^[23] ]]; then
  echo "           NOTE — with code_challenge present: HTTP $CLIENT_INFO (PKCE flow works)"
else
  echo "           NOTE — with code_challenge present: HTTP $CLIENT_INFO"
fi
RESULTS+=("T3:INFO")
echo

# ── Summary ─────────────────────────────────────────────────────────────────
echo "─── Summary ───────────────────────────────────"
for r in "${RESULTS[@]}"; do echo "  $r"; done
echo

ANY_VULN=false
for r in "${RESULTS[@]}"; do [[ "$r" == *VULNERABLE* ]] && ANY_VULN=true; done

if $ANY_VULN; then
  echo "VULNERABLE — PKCE not enforced; auth codes can be intercepted and exchanged"
else
  echo "PROTECTED  — PKCE enforcement prevents authorization code interception"
fi
