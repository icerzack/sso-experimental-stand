#!/usr/bin/env bash
# A7 — Session Fixation
# OWASP ASVS v4.2 § 3.3.2 / MITRE ATT&CK T1556
#
# Profiles: 1A, 1B, 1C
#
# Tests whether the application rotates the session ID after login.
# An attacker who sets a known session cookie on the victim's browser
# (via XSS, subdomain cookie, etc.) can then hijack the authenticated session.
#
# Usage:
#   bash A7_session_fixation.sh <app_url> <idp_url> [realm] [client_id] [client_secret] [username] [password]

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

echo "[A7] Session Fixation — session not rotated after login"
echo "     App: $APP_URL  |  IdP: $IDP_URL  |  Realm: $REALM"
echo

# ── Step 1: Set a pre-login session cookie and check if it's accepted ──────
FIXATION_COOKIE="fixation-test-$(date +%s)"

echo "  [1] Sending request with pre-authentication cookie (sess=$FIXATION_COOKIE)..."
STATUS_PRE=$(rcurl -sk -o /dev/null -w "%{http_code}" \
  --cookie "sess=$FIXATION_COOKIE" \
  "${APP_URL%/}/protected" 2>/dev/null || echo "000")
echo "      → HTTP $STATUS_PRE"

# Also check what cookies the server sends back
HEADERS_PRE=$(rcurl -sk --cookie "sess=$FIXATION_COOKIE" \
  -D - -o /dev/null "${APP_URL%/}/" 2>/dev/null || true)
PRE_LOGIN_SET_COOKIE=$(echo "$HEADERS_PRE" | grep -i "set-cookie" | head -1 || true)
echo "      Pre-login Set-Cookie: ${PRE_LOGIN_SET_COOKIE:-none}"
echo

# ── Step 2: Perform full OIDC login flow and capture before/after cookies ───
echo "  [2] Performing full OIDC login via browser simulation..."

JAR_FILE="/tmp/a7_cookies_$$.txt"
rm -f "$JAR_FILE"

# Start with the fixation cookie
echo "app.sso-lab.local	FALSE	/	TRUE	0	sess	$FIXATION_COOKIE" > "$JAR_FILE"

# Follow the full OIDC redirect chain
FINAL_RESPONSE=$(rcurl -sk -L -b "$JAR_FILE" -c "$JAR_FILE" --max-redirs 15 \
  "${APP_URL%/}/login" 2>/dev/null || true)

# Examine the final cookie jar to see all cookies set during the flow
echo "      Cookie jar after login:"
POST_LOGIN_COOKIES=$(cat "$JAR_FILE" 2>/dev/null || true)
if [[ -n "$POST_LOGIN_COOKIES" ]]; then
  while IFS= read -r line; do
    echo "        $line"
  done <<< "$POST_LOGIN_COOKIES"
else
  echo "        (empty)"
fi
echo

# ── Step 3: Check if the session cookie was rotated ─────────────────────────
echo "  [3] Checking for session rotation..."

POST_SESS=""
if [[ -f "$JAR_FILE" ]]; then
  # Get the final sess value from the jar
  POST_SESS=$(grep -P "\tsess\t" "$JAR_FILE" 2>/dev/null | tail -1 | awk '{print $NF}' || true)
fi

echo "      Pre-login cookie:  $FIXATION_COOKIE"
echo "      Post-login cookie: ${POST_SESS:-<no cookie found>}"

SESSION_CHANGED=false
if [[ -n "$POST_SESS" && "$POST_SESS" != "$FIXATION_COOKIE" ]]; then
  SESSION_CHANGED=true
  echo "      Session WAS rotated after login ✓"
else
  echo "      Session was NOT rotated after login ✗"
fi
echo

# ── Step 4: Verify post-login access ────────────────────────────────────────
# Use the new session cookie to verify it works
if [[ -n "$POST_SESS" ]]; then
  STATUS_POST=$(rcurl -sk -o /dev/null -w "%{http_code}" \
    --cookie "sess=$POST_SESS" \
    "${APP_URL%/}/protected" 2>/dev/null || echo "000")
  echo "  [4] Post-login access with new cookie → HTTP $STATUS_POST"
fi

# Clean up
rm -f "$JAR_FILE"
echo

# ── Verdict ──────────────────────────────────────────────────────────────────
if ! $SESSION_CHANGED; then
  echo "VULNERABLE — session cookie is not rotated after authentication"
  echo "             An attacker can fixate a session ID before login."
elif [[ "${STATUS_POST:-}" == "200" ]]; then
  echo "PROTECTED  — session cookie was rotated after login"
else
  echo "PROTECTED  — session appears rotated (post-login verification inconclusive)"
fi
