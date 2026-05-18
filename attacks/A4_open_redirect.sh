#!/usr/bin/env bash
# A4 — Open Redirect (redirect_uri manipulation)
# OWASP ASVS v4.2 § 3.5.2 / RFC 6749 §10.6
# MITRE ATT&CK T1078
#
# Profiles: 1A, 1C
#
# Sends an authorization request with an attacker-controlled redirect_uri.
# A misconfigured IdP will redirect the user's browser (and auth code) to
# the attacker's server.
#
# Usage:
#   bash A4_open_redirect.sh <idp_url> [realm] [client_id]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

IDP_URL="${1:?Usage: $0 <idp_url> [realm] [client_id]}"
REALM="${2:-sso-lab}"
CLIENT_ID="${3:-sso-test-app}"
EVIL_URI="https://evil.example.com/steal"

AUTH_ENDPOINT="${IDP_URL%/}/realms/${REALM}/protocol/openid-connect/auth"
STATE="teststate_a4_$(date +%s)"

echo "[A4] Open Redirect — redirect_uri manipulation"
echo "     IdP: $IDP_URL  |  Realm: $REALM  |  Client: $CLIENT_ID"
echo "     Evil URI: $EVIL_URI"
echo

# ── Pre-flight: verify IdP is reachable ──────────────────────────────────────
PREFLIGHT=$(rcurl -sk -o /dev/null -w "%{http_code}" "${IDP_URL%/}/" 2>/dev/null || echo "000")
if [[ "$PREFLIGHT" == "000" ]]; then
  echo "SKIPPED — IdP at $IDP_URL is unreachable"
  exit 0
fi

RESULTS=()

# ── Test 1: Fully external redirect_uri ─────────────────────────────────────
echo "  [Test 1] redirect_uri = $EVIL_URI  (fully external)"
ENCODED_EVIL=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$EVIL_URI")
URL1="${AUTH_ENDPOINT}?client_id=${CLIENT_ID}&response_type=code&scope=openid&redirect_uri=${ENCODED_EVIL}&state=${STATE}"

RESPONSE1=$(rcurl -si --max-redirs 5 "$URL1" 2>/dev/null || true)
LOCATION1=$(echo "$RESPONSE1" | grep -i "^location:" | tail -1 || true)
HTTP_STATUS1=$(echo "$RESPONSE1" | head -1 | awk '{print $2}' || true)

echo "           HTTP $HTTP_STATUS1"
if [[ -n "$LOCATION1" ]]; then
  echo "           Location: ${LOCATION1:0:120}"
fi

ERROR_PARAM1=$(echo "$LOCATION1" | grep -o "error=[^&]*" || true)
BODY1=$(echo "$RESPONSE1" | sed -n '/^\r$/,$p')

if echo "$LOCATION1" | grep -q "evil.example.com"; then
  echo "           VULNERABLE — IdP redirected to attacker-controlled URI"
  RESULTS+=("T1:VULNERABLE")
elif [[ -n "$ERROR_PARAM1" ]] || echo "$BODY1" | grep -qi "invalid_redirect_uri\|Redirect URI mismatch"; then
  echo "           PROTECTED  — IdP rejected invalid redirect_uri ($ERROR_PARAM1)"
  RESULTS+=("T1:PROTECTED")
elif [[ "$HTTP_STATUS1" == "200" ]]; then
  # Keycloak shows login page even for invalid redirect_uri — check if error is in page
  if echo "$BODY1" | grep -qi "invalid_redirect\|Redirect URI\|error"; then
    echo "           PROTECTED  — error shown on login page"
    RESULTS+=("T1:PROTECTED")
  else
    echo "           VULNERABLE — login form shown without rejecting redirect_uri"
    RESULTS+=("T1:VULNERABLE")
  fi
else
  echo "           PROTECTED  — request rejected (HTTP $HTTP_STATUS1)"
  RESULTS+=("T1:PROTECTED")
fi
echo

# ── Test 2: Subdomain bypass (app.sso-lab.local.evil.com) ───────────────────
EVIL_SUBDOMAIN="https://app.sso-lab.local.evil.com/steal"
ENCODED_SUBDOMAIN=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$EVIL_SUBDOMAIN")
URL2="${AUTH_ENDPOINT}?client_id=${CLIENT_ID}&response_type=code&scope=openid&redirect_uri=${ENCODED_SUBDOMAIN}&state=${STATE}"

echo "  [Test 2] redirect_uri = $EVIL_SUBDOMAIN  (subdomain confusion)"
RESPONSE2=$(rcurl -si --max-redirs 5 "$URL2" 2>/dev/null || true)
LOCATION2=$(echo "$RESPONSE2" | grep -i "^location:" | tail -1 || true)
HTTP_STATUS2=$(echo "$RESPONSE2" | head -1 | awk '{print $2}' || true)

echo "           HTTP $HTTP_STATUS2"
if [[ -n "$LOCATION2" ]]; then
  echo "           Location: ${LOCATION2:0:120}"
fi

if echo "$LOCATION2" | grep -q "evil.com"; then
  echo "           VULNERABLE — subdomain bypass accepted"
  RESULTS+=("T2:VULNERABLE")
elif echo "$LOCATION2" | grep -qi "error=" ; then
  echo "           PROTECTED  — subdomain redirect rejected"
  RESULTS+=("T2:PROTECTED")
else
  echo "           PROTECTED  — subdomain redirect not followed"
  RESULTS+=("T2:PROTECTED")
fi
echo

# ── Test 3: Path traversal (/callback/../attacker) ──────────────────────────
PATH_TRAVERSAL="https://app.sso-lab.local/callback/../evil"
ENCODED_PATH=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$PATH_TRAVERSAL")
URL3="${AUTH_ENDPOINT}?client_id=${CLIENT_ID}&response_type=code&scope=openid&redirect_uri=${ENCODED_PATH}&state=${STATE}"

echo "  [Test 3] redirect_uri = $PATH_TRAVERSAL  (path traversal)"
RESPONSE3=$(rcurl -si --max-redirs 5 "$URL3" 2>/dev/null || true)
LOCATION3=$(echo "$RESPONSE3" | grep -i "^location:" | tail -1 || true)
HTTP_STATUS3=$(echo "$RESPONSE3" | head -1 | awk '{print $2}' || true)

echo "           HTTP $HTTP_STATUS3"
if [[ -n "$LOCATION3" ]]; then
  echo "           Location: ${LOCATION3:0:120}"
fi

if echo "$LOCATION3" | grep -q "\.\./evil\|/evil"; then
  echo "           VULNERABLE — path traversal accepted"
  RESULTS+=("T3:VULNERABLE")
elif echo "$LOCATION3" | grep -qi "error="; then
  echo "           PROTECTED  — path traversal rejected"
  RESULTS+=("T3:PROTECTED")
else
  BODY3=$(echo "$RESPONSE3" | sed -n '/^\r$/,$p')
  if echo "$BODY3" | grep -qi "invalid_redirect\|Redirect URI mismatch"; then
    echo "           PROTECTED  — path traversal rejected (shown in body)"
    RESULTS+=("T3:PROTECTED")
  else
    echo "           VULNERABLE — path traversal accepted (no rejection shown)"
    RESULTS+=("T3:VULNERABLE")
  fi
fi
echo

# ── Summary ─────────────────────────────────────────────────────────────────
echo "─── Summary ───────────────────────────────────"
for r in "${RESULTS[@]}"; do echo "  $r"; done
echo

ANY_VULN=false
for r in "${RESULTS[@]}"; do [[ "$r" == *VULNERABLE* ]] && ANY_VULN=true; done

if $ANY_VULN; then
  echo "VULNERABLE — open redirect bypass succeeded (see above)"
else
  echo "PROTECTED  — all redirect_uri checks passed"
fi
