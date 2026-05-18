#!/usr/bin/env bash
# A8 — CSRF на logout
# OWASP ASVS v4.2 § 3.5.1 / RFC 6749 §10.12
# MITRE ATT&CK T1534
#
# Profiles: 1A, 1B, 1C
#
# Tests whether the logout endpoint is vulnerable to Cross-Site Request Forgery.
# If a logged-in user visits an attacker's page that sends a POST/GET to the
# logout endpoint, the user is forcibly logged out without their consent.
#
# A protected application should:
#   1. Require CSRF token on state-changing requests (POST /logout)
#   2. Use SameSite=Strict/Lax on session cookies
#   3. Not allow GET requests for logout
#
# Usage:
#   bash A8_csrf_logout.sh <app_url> <idp_url> [realm] [client_id] [client_secret] [username] [password]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

APP_URL="${1:?Usage: $0 <app_url> <idp_url> [realm] ...}"
IDP_URL="${2:?}"
REALM="${3:-sso-lab}"
CLIENT_ID="${4:-sso-test-app}"
CLIENT_SECRET="${5:-testpass123}"
USERNAME="${6:-testuser}"
PASSWORD="${7:-password123}"

echo "[A8] CSRF на logout"
echo "     App: $APP_URL  |  IdP: $IDP_URL  |  Realm: $REALM"
echo

RESULTS=()

# ── Step 1: Authenticate and obtain session ──────────────────────────────────
echo "  [1] Authenticating to get valid session..."

JAR_FILE="/tmp/a8_cookies_$$.txt"
rm -f "$JAR_FILE"

# Perform OIDC login via redirect chain
rcurl -sk -L -c "$JAR_FILE" --max-redirs 15 \
  "${APP_URL%/}/login" \
  -o /tmp/a8_login_page_$$.html 2>/dev/null || true

# Check if we landed on Keycloak login form (need to submit credentials)
FORM_ACTION=$(grep -oP 'action="([^"]+)"' /tmp/a8_login_page_$$.html 2>/dev/null | head -1 | sed 's/action="//;s/"$//' || true)
if [[ -n "$FORM_ACTION" && "$FORM_ACTION" == *"keycloak"* ]]; then
  FORM_ACTION=$(echo "$FORM_ACTION" | sed 's/&amp;/\&/g')
  rcurl -sk -L -c "$JAR_FILE" -b "$JAR_FILE" --max-redirs 15 \
    -X POST "$FORM_ACTION" \
    -d "username=${USERNAME}" \
    -d "password=${PASSWORD}" \
    -d "credentialId=" \
    -o /dev/null 2>/dev/null || true
fi

SESS=""
if [[ -f "$JAR_FILE" ]]; then
  SESS=$(grep -P "\tsess\t" "$JAR_FILE" 2>/dev/null | tail -1 | awk '{print $NF}' || true)
fi

if [[ -z "$SESS" ]]; then
  echo "      FAILED — could not obtain session cookie"
  rm -f "$JAR_FILE" /tmp/a8_login_page_$$.html
  echo
  echo "SKIPPED"
  exit 0
fi

echo "      Got session: ${SESS:0:20}…"
echo

# Verify the session works
STATUS_AUTH=$(rcurl -sk -o /dev/null -w "%{http_code}" \
  --cookie "sess=$SESS" \
  "${APP_URL%/}/protected" 2>/dev/null || echo "000")
echo "      Session verification → HTTP $STATUS_AUTH"

if [[ "$STATUS_AUTH" != "200" ]]; then
  echo "      WARNING — session not valid, results may be unreliable"
fi
echo

# ── Step 2: Test GET /logout (should not be allowed) ────────────────────────
echo "  [Test 1] GET /logout (cross-site request simulation)"
RESP_FILE="/tmp/a8_t1_$$.txt"
GET_HEADERS=$(rcurl -sk -D - -o "$RESP_FILE" --cookie "sess=$SESS" \
  "${APP_URL%/}/logout" 2>/dev/null || true)
STATUS_GET=$(echo "$GET_HEADERS" | head -1 | awk '{print $2}' || true)

# Check Set-Cookie for SameSite flag
SET_COOKIE_GET=$(echo "$GET_HEADERS" | grep -i "^set-cookie:" || true)
rm -f "$RESP_FILE"

if [[ "$STATUS_GET" == "302" || "$STATUS_GET" == "200" ]]; then
  echo "           → HTTP $STATUS_GET (logout succeeded via GET)"
  if [[ -n "$SET_COOKIE_GET" ]]; then
    if echo "$SET_COOKIE_GET" | grep -qi "SameSite"; then
      SAMESITE_VAL=$(echo "$SET_COOKIE_GET" | grep -oi "SameSite=[^;]*" || true)
      echo "           Cookie: $SAMESITE_VAL"
    else
      echo "           No SameSite attribute on Set-Cookie!"
    fi
  fi
  RESULTS+=("T1:VULNERABLE")
else
  echo "           → HTTP $STATUS_GET (GET logout not functional or rejected)"
  RESULTS+=("T1:PROTECTED")
fi
echo

# Re-authenticate for next test (session may be destroyed)
rm -f "$JAR_FILE"
rcurl -sk -L -c "$JAR_FILE" --max-redirs 15 \
  "${APP_URL%/}/login" -o /tmp/a8_reauth_$$.html 2>/dev/null || true

FORM_ACTION2=$(grep -oP 'action="([^"]+)"' /tmp/a8_reauth_$$.html 2>/dev/null | head -1 | sed 's/action="//;s/"$//' || true)
if [[ -n "$FORM_ACTION2" && "$FORM_ACTION2" == *"keycloak"* ]]; then
  FORM_ACTION2=$(echo "$FORM_ACTION2" | sed 's/&amp;/\&/g')
  rcurl -sk -L -c "$JAR_FILE" -b "$JAR_FILE" --max-redirs 15 \
    -X POST "$FORM_ACTION2" \
    -d "username=${USERNAME}" \
    -d "password=${PASSWORD}" \
    -d "credentialId=" \
    -o /dev/null 2>/dev/null || true
fi

SESS2=""
if [[ -f "$JAR_FILE" ]]; then
  SESS2=$(grep -P "\tsess\t" "$JAR_FILE" 2>/dev/null | tail -1 | awk '{print $NF}' || true)
fi

# ── Step 3: Test POST /logout without CSRF token ────────────────────────────
echo "  [Test 2] POST /logout without CSRF token"
RESP_FILE="/tmp/a8_t2_$$.txt"
STATUS_POST=$(rcurl -sk -o "$RESP_FILE" -w "%{http_code}" \
  -X POST --cookie "sess=${SESS2:-$SESS}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  "${APP_URL%/}/logout" 2>/dev/null || echo "000")

BODY2=$(head -c 200 "$RESP_FILE" 2>/dev/null || true)
rm -f "$RESP_FILE"

echo "           → HTTP $STATUS_POST"
if [[ "$STATUS_POST" == "200" || "$STATUS_POST" == "302" ]]; then
  # Check if session was actually destroyed
  STATUS_VERIFY=$(rcurl -sk -o /dev/null -w "%{http_code}" \
    --cookie "sess=${SESS2:-$SESS}" \
    "${APP_URL%/}/protected" 2>/dev/null || echo "000")

  if [[ "$STATUS_VERIFY" != "200" ]]; then
    echo "           VULNERABLE — POST /logout works without CSRF token, session was destroyed"
    echo "           Post-logout access check → HTTP $STATUS_VERIFY"
    RESULTS+=("T2:VULNERABLE")
  else
    echo "           PROTECTED  — POST /logout executed but session still valid (stateless?)"
    RESULTS+=("T2:PROTECTED")
  fi
else
  echo "           PROTECTED  — POST /logout rejected or requires CSRF token (HTTP $STATUS_POST)"
  RESULTS+=("T2:PROTECTED")
fi
echo

# ── Step 4: Check SameSite attribute on original session cookie ─────────────
echo "  [Test 3] Checking SameSite attribute on session cookies..."
ALL_COOKIES=$(cat "$JAR_FILE" 2>/dev/null || true)
if [[ -n "$ALL_COOKIES" ]]; then
  while IFS= read -r line; do
    cookiename=$(echo "$line" | awk '{print $6}')
    if [[ "$cookiename" == "sess" || "$cookiename" == "session" ]]; then
      echo "           Found: $line"
    fi
  done <<< "$ALL_COOKIES"
fi

# Also check from server response headers
HEADER_CHECK=$(rcurl -sk -D - -o /dev/null --cookie "sess=${SESS2:-$SESS}" \
  "${APP_URL%/}/protected" 2>/dev/null || true)
SESSION_SAMESITE=$(echo "$HEADER_CHECK" | grep -i "set-cookie.*sess\|set-cookie.*session" | head -1 || true)

if [[ -n "$SESSION_SAMESITE" ]]; then
  if echo "$SESSION_SAMESITE" | grep -qi "SameSite"; then
    SAMESITE_ATTR=$(echo "$SESSION_SAMESITE" | grep -oi "SameSite=[^;]*" || true)
    echo "           Session cookie has $SAMESITE_ATTR ✓"
    if echo "$SAMESITE_ATTR" | grep -qi "None"; then
      echo "           WARNING — SameSite=None provides no CSRF protection!"
      RESULTS+=("T3:VULNERABLE")
    else
      RESULTS+=("T3:PROTECTED")
    fi
  else
    echo "           Session cookie lacks SameSite attribute ✗"
    RESULTS+=("T3:VULNERABLE")
  fi
else
  echo "           Could not determine SameSite from headers"
  RESULTS+=("T3:INFO")
fi
echo

# Clean up
rm -f "$JAR_FILE" /tmp/a8_login_page_$$.html /tmp/a8_reauth_$$.html

# ── Summary ─────────────────────────────────────────────────────────────────
echo "─── Summary ───────────────────────────────────"
for r in "${RESULTS[@]}"; do echo "  $r"; done
echo

ANY_VULN=false
for r in "${RESULTS[@]}"; do [[ "$r" == *VULNERABLE* ]] && ANY_VULN=true; done

if $ANY_VULN; then
  echo "VULNERABLE — logout is susceptible to CSRF attacks"
else
  echo "PROTECTED  — logout endpoint is properly protected against CSRF"
fi
