#!/usr/bin/env bash
# A9 — Credential Stuffing (нет rate limiting)
# OWASP ASVS v4.2 § 2.2.1 / MITRE ATT&CK T1110.004
#
# Profiles: 1A, 1C
#
# Sends a burst of authentication attempts against the IdP login endpoint.
# If no rate limiting is in place, an attacker can try unlimited passwords.
#
# This script tests two vectors:
#   1. Direct token endpoint (ROPC) — used by API clients
#   2. Browser login form — the interactive login page
#
# Usage:
#   bash A9_credential_stuffing.sh <idp_url> [realm] [client_id] [client_secret] [username]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

IDP_URL="${1:?Usage: $0 <idp_url> [realm] [client_id] [client_secret] [username]}"
REALM="${2:-sso-lab}"
CLIENT_ID="${3:-sso-test-app}"
CLIENT_SECRET="${4:-testpass123}"
USERNAME="${5:-testuser}"

WORDLIST="${SCRIPT_DIR}/../wordlists/top100_passwords.txt"
MAX_ATTEMPTS=20

TOKEN_URL="${IDP_URL%/}/realms/${REALM}/protocol/openid-connect/token"

echo "[A9] Credential Stuffing — no rate limiting"
echo "     IdP: $IDP_URL  |  Realm: $REALM  |  User: $USERNAME"
echo "     Max attempts: $MAX_ATTEMPTS"
echo

# ── Pre-flight: verify IdP is reachable ──────────────────────────────────────
PREFLIGHT=$(rcurl -sk -o /dev/null -w "%{http_code}" "${IDP_URL%/}/" 2>/dev/null || echo "000")
if [[ "$PREFLIGHT" == "000" ]]; then
  echo "SKIPPED — IdP at $IDP_URL is unreachable"
  exit 0
fi

if [[ ! -f "$WORDLIST" ]]; then
  echo "  Wordlist not found at $WORDLIST"
  echo "SKIPPED"
  exit 0
fi

mapfile -t PASSWORDS < <(head -$MAX_ATTEMPTS "$WORDLIST" | grep -v '^$' || true)

RESULTS=()
RATE_LIMITED=false
SUCCESS_FOUND=false

# ── Test 1: ROPC token endpoint burst ───────────────────────────────────────
echo "  [Test 1] Token endpoint burst (${#PASSWORDS[@]} passwords via ROPC)"

rate_limited_t1=false
success_t1=false
attempt=0

for pwd in "${PASSWORDS[@]}"; do
  attempt=$((attempt + 1))

  RESP=$(rcurl -sk -o /dev/null -w "%{http_code}" \
    -X POST "$TOKEN_URL" \
    -d "grant_type=password" \
    -d "client_id=${CLIENT_ID}" \
    -d "client_secret=${CLIENT_SECRET}" \
    -d "username=${USERNAME}" \
    -d "password=${pwd}" \
    2>/dev/null || echo "000")

  MARKER=""
  if [[ "$RESP" == "200" ]]; then
    success_t1=true
    MARKER=" ← SUCCESS"
  elif [[ "$RESP" == "429" ]]; then
    rate_limited_t1=true
    MARKER=" ← RATE LIMITED"
  fi

  printf "      [%03d] %-25s → HTTP %s%s\n" "$attempt" "$pwd" "$RESP" "$MARKER"

  if $rate_limited_t1 || $success_t1; then
    break
  fi
done

echo
if $success_t1; then
  echo "           Password found at attempt $attempt (no rate limit before success)"
  RESULTS+=("T1:VULNERABLE")
elif $rate_limited_t1; then
  echo "           Rate limiting triggered after $attempt attempt(s) ✓"
  RESULTS+=("T1:PROTECTED")
else
  echo "           No rate limiting detected across $attempt attempts"
  RESULTS+=("T1:VULNERABLE")
fi
echo

# ── Test 2: Keycloak login form ─────────────────────────────────────────────
echo "  [Test 2] Login form burst (${#PASSWORDS[@]} passwords)"

LOGIN_URL="${IDP_URL%/}/realms/${REALM}/login-actions/authenticate"
KC_SESSION=""

rate_limited_t2=false
success_t2=false
attempt2=0

for pwd in "${PASSWORDS[@]}"; do
  attempt2=$((attempt2 + 1))

  # First get a fresh login page to obtain the form action URL with session code
  LOGIN_PAGE=$(rcurl -sk -L -c "/tmp/a9_kc_$$.txt" \
    "${IDP_URL%/}/realms/${REALM}/protocol/openid-connect/auth?client_id=${CLIENT_ID}&response_type=code&scope=openid&redirect_uri=https://app.sso-lab.local/callback&state=test_a9" \
    2>/dev/null || true)

  FORM_ACTION=$(echo "$LOGIN_PAGE" | grep -oP 'id="kc-form-login"[^>]*action="[^"]*"' | grep -oP 'action="[^"]*"' | sed 's/action="//;s/"$//' || true)

  if [[ -z "$FORM_ACTION" ]]; then
    # Try another pattern
    FORM_ACTION=$(echo "$LOGIN_PAGE" | grep -oP 'form action="[^"]*"' | head -1 | sed 's/form action="//;s/"$//' || true)
  fi

  if [[ -z "$FORM_ACTION" ]]; then
    continue
  fi

  # Replace HTML entities
  FORM_ACTION=$(echo "$FORM_ACTION" | sed 's/&amp;/\&/g')
  # Make absolute if relative
  if [[ "$FORM_ACTION" != http* ]]; then
    FORM_ACTION="${IDP_URL}${FORM_ACTION}"
  fi

  RESP2=$(rcurl -sk -o /dev/null -w "%{http_code}" \
    -b "/tmp/a9_kc_$$.txt" \
    -X POST "$FORM_ACTION" \
    -d "username=${USERNAME}" \
    -d "password=${pwd}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    2>/dev/null || echo "000")

  MARKER=""
  if [[ "$RESP2" == "302" ]]; then
    # Check if redirect is back to app (success) or stays on error page
    HEADERS_CHECK=$(rcurl -sk -D - -o /dev/null \
      -b "/tmp/a9_kc_$$.txt" \
      -X POST "$FORM_ACTION" \
      -d "username=${USERNAME}" \
      -d "password=${PWD}" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      2>/dev/null || true)
    LOCATION=$(echo "$HEADERS_CHECK" | grep -i "^location:" | head -1 || true)
    if echo "$LOCATION" | grep -q "error\|invalid_credentials"; then
      MARKER=""
    else
      success_t2=true
      MARKER=" ← POSSIBLE SUCCESS"
    fi
  elif [[ "$RESP2" == "429" ]]; then
    rate_limited_t2=true
    MARKER=" ← RATE LIMITED"
  elif [[ "$RESP2" == "200" ]]; then
    # Still on login page = wrong password; check for error message
    MARKER=""
  fi

  printf "      [%03d] %-25s → HTTP %s%s\n" "$attempt2" "$pwd" "$RESP2" "$MARKER"

  rm -f "/tmp/a9_kc_$$.txt"

  if $rate_limited_t2 || $success_t2; then
    break
  fi
done

rm -f "/tmp/a9_kc_$$.txt"

echo
if $success_t2; then
  RESULTS+=("T2:VULNERABLE")
elif $rate_limited_t2; then
  echo "           Rate limiting triggered after $attempt2 form attempt(s) ✓"
  RESULTS+=("T2:PROTECTED")
elif [[ "$attempt2" -eq 0 ]]; then
  echo "           Could not reach login form"
  RESULTS+=("T2:SKIP")
else
  echo "           No rate limiting detected across $attempt2 form attempts"
  RESULTS+=("T2:VULNERABLE")
fi
echo

# ── Summary ─────────────────────────────────────────────────────────────────
echo "─── Summary ───────────────────────────────────"
for r in "${RESULTS[@]}"; do echo "  $r"; done
echo

ANY_VULN=false
ANY_PROTECTED=false
for r in "${RESULTS[@]}"; do
  [[ "$r" == *VULNERABLE* ]] && ANY_VULN=true
  [[ "$r" == *PROTECTED* ]] && ANY_PROTECTED=true
done

if $ANY_VULN; then
  echo "VULNERABLE — no rate limiting on authentication endpoints"
elif $ANY_PROTECTED; then
  echo "PROTECTED  — rate limiting is enforced on authentication endpoints"
else
  echo "INCONCLUSIVE — could not determine rate limiting status"
fi
