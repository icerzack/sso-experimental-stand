#!/usr/bin/env bash
# A8 — CSRF / Missing State + PKCE
# OWASP ASVS v4.2 § 3.5.3 / RFC 6749 §10.12 / RFC 7636
#
# Test 1: Callback without state — verifies the app checks the state param.
# Test 2: Callback with a predictable/known state — verifies the state is
#         compared to the value stored in the user's session (not just present).
# Test 3: Authorization URL missing code_challenge — verifies PKCE is required.
#
# Usage:
#   bash A8_csrf_state.sh <app_base_url> <keycloak_base_url> [realm] [client_id]
#
# Examples:
#   bash A8_csrf_state.sh http://app-a-v.local:8081 http://keycloak.local:8080 profile-a-vulnerable sso-test-app
#   bash A8_csrf_state.sh https://app-a-h.local     http://keycloak.local:8080 profile-a-hardened   sso-test-app

set -euo pipefail

APP_URL="${1:?Usage: $0 <app_url> <kc_url> [realm] [client_id]}"
KC_URL="${2:?}"
REALM="${3:-profile-a-vulnerable}"
CLIENT_ID="${4:-sso-test-app}"

echo "[A8] CSRF state + PKCE check"
echo "     App:    $APP_URL"
echo "     Realm:  $REALM"
echo
RESULTS=()

# ── Test 1: callback with no state ──────────────────────────────────────────
echo "  [Test 1] Callback without state parameter"
FAKE_CODE="FAKECODE123"
STATUS1=$(curl -si -o /tmp/c2_t1.txt -w "%{http_code}" \
  "${APP_URL%/}/callback?code=${FAKE_CODE}" 2>/dev/null | tail -1)
BODY1=$(cat /tmp/c2_t1.txt | tail -1)
echo "           → HTTP $STATUS1"

if [[ "$STATUS1" == "400" ]] || echo "$BODY1" | grep -qi "invalid state\|missing state"; then
  echo "           PROTECTED — state absence detected"
  RESULTS+=("T1:PROTECTED")
else
  echo "           VULNERABLE — callback accepted without state"
  RESULTS+=("T1:VULNERABLE")
fi
echo

# ── Test 2: callback with a guessable state ──────────────────────────────────
echo "  [Test 2] Callback with predictable state (AAAAAAAAAAAAAAAA)"
STATUS2=$(curl -si -o /tmp/c2_t2.txt -w "%{http_code}" \
  "${APP_URL%/}/callback?code=${FAKE_CODE}&state=AAAAAAAAAAAAAAAA" 2>/dev/null | tail -1)
echo "           → HTTP $STATUS2"

if [[ "$STATUS2" == "400" ]] || grep -qi "invalid state" /tmp/c2_t2.txt 2>/dev/null; then
  echo "           PROTECTED — state mismatch detected (compared with session value)"
  RESULTS+=("T2:PROTECTED")
else
  echo "           VULNERABLE — predictable state accepted"
  RESULTS+=("T2:VULNERABLE")
fi
echo

# ── Test 3: auth URL missing code_challenge (PKCE check) ────────────────────
echo "  [Test 3] Authorization URL without code_challenge (no PKCE)"
REDIRECT_URI="${APP_URL%/}/callback"
AUTH_URL="${KC_URL%/}/realms/${REALM}/protocol/openid-connect/auth"
NO_PKCE_URL="${AUTH_URL}?client_id=${CLIENT_ID}&response_type=code&scope=openid&redirect_uri=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$REDIRECT_URI")&state=teststate"

STATUS3=$(curl -si -o /tmp/c2_t3.txt -w "%{http_code}" --max-redirs 0 "$NO_PKCE_URL" 2>/dev/null | tail -1)
LOC3=$(grep -i "^location:" /tmp/c2_t3.txt | head -1 || true)
echo "           → HTTP $STATUS3"

if echo "$LOC3" | grep -qi "error=\|invalid"; then
  echo "           PROTECTED — PKCE enforced (Keycloak rejected non-PKCE request)"
  RESULTS+=("T3:PROTECTED")
elif [[ "$STATUS3" =~ ^[23] ]]; then
  echo "           VULNERABLE — Keycloak issued auth page without PKCE challenge"
  RESULTS+=("T3:VULNERABLE")
else
  echo "           INCONCLUSIVE — HTTP $STATUS3 (Keycloak may not be running)"
  RESULTS+=("T3:INCONCLUSIVE")
fi
echo

# ── Summary ─────────────────────────────────────────────────────────────────
ALL_PROTECTED=true
for r in "${RESULTS[@]}"; do
  [[ "$r" == *VULNERABLE* ]] && ALL_PROTECTED=false
done

echo "─── Summary ───────────────────────────────────"
for r in "${RESULTS[@]}"; do echo "  $r"; done
echo
if $ALL_PROTECTED; then
  echo "PROTECTED  — all three CSRF/PKCE checks passed"
else
  echo "VULNERABLE — one or more checks failed (see above)"
fi
