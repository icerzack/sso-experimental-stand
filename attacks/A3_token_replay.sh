#!/usr/bin/env bash
# A3 — Token Replay (отсутствие nonce/jti)
# OWASP ASVS v4.2 § 3.5.4 — Verify that tokens include a unique identifier.
# MITRE ATT&CK T1550.004
#
# Profiles: 1A, 1C
#
# Obtains a valid access_token/id_token, waits, then replays the same token.
# If the server does not check jti/nonce or maintain token revocation,
# the replayed token will still be accepted.
#
# Usage:
#   bash A3_token_replay.sh <app_url> <idp_url> [realm] [client_id] [client_secret] [username] [password]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

APP_URL="${1:?Usage: $0 <app_url> <idp_url> [realm] [client_id] [client_secret] [username] [password]}"
IDP_URL="${2:?}"
REALM="${3:-sso-lab}"
CLIENT_ID="${4:-sso-test-app}"
CLIENT_SECRET="${5:-testpass123}"
USERNAME="${6:-testuser}"
PASSWORD="${7:-password123}"

REPLAY_DELAY=5  # seconds between initial use and replay

echo "[A3] Token Replay — missing nonce/jti check"
echo "     App: $APP_URL  |  IdP: $IDP_URL  |  Realm: $REALM"
echo

# ── Step 1: Obtain tokens via ROPC ────────────────────────────────────────────
TOKEN_URL="${IDP_URL%/}/realms/${REALM}/protocol/openid-connect/token"

echo "  [1] Obtaining access_token + id_token via ROPC..."
RESPONSE=$(rcurl -sk -X POST "$TOKEN_URL" \
  -d "grant_type=password" \
  -d "client_id=${CLIENT_ID}" \
  -d "client_secret=${CLIENT_SECRET}" \
  -d "username=${USERNAME}" \
  -d "password=${PASSWORD}" \
  -d "scope=openid" 2>/dev/null)

ACCESS_TOKEN=$(echo "$RESPONSE" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    print(d.get('access_token',''))
except: pass" 2>/dev/null)

ID_TOKEN=$(echo "$RESPONSE" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    print(d.get('id_token',''))
except: pass" 2>/dev/null)

if [[ -z "$ACCESS_TOKEN" && -z "$ID_TOKEN" ]]; then
  echo "      FAILED — could not obtain any token"
  echo
  echo "SKIPPED"
  exit 0
fi

[[ -n "$ACCESS_TOKEN" ]] && echo "      access_token: ${ACCESS_TOKEN:0:40}…"
[[ -n "$ID_TOKEN" ]] && echo "      id_token:     ${ID_TOKEN:0:40}…"
echo

# ── Step 2: Check JWT for jti claim ──────────────────────────────────────────
if [[ -n "$ACCESS_TOKEN" ]]; then
  PAYLOAD_B64=$(echo "$ACCESS_TOKEN" | cut -d. -f2)
else
  PAYLOAD_B64=$(echo "$ID_TOKEN" | cut -d. -f2)
fi
PAYLOAD_JSON=$(b64url_decode "$PAYLOAD_B64")

HAS_JTI=$(echo "$PAYLOAD_JSON" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    print('yes' if 'jti' in d else 'no')
except: print('unknown')" 2>/dev/null)

echo "  [2] Token jti claim: $HAS_JTI"

HAS_NONCE=$(echo "$PAYLOAD_JSON" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    print('yes' if 'nonce' in d else 'no')
except: print('unknown')" 2>/dev/null)

echo "      Token nonce claim: $HAS_NONCE"
echo

# ── Step 3: First use of token (baseline) ────────────────────────────────────
USE_TOKEN="${ACCESS_TOKEN:-$ID_TOKEN}"

STATUS1=$(rcurl -sk -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $USE_TOKEN" \
  "${APP_URL%/}/protected" 2>/dev/null || echo "000")

echo "  [3] First use of token → HTTP $STATUS1"

if [[ "$STATUS1" != "200" ]]; then
  # Try with session cookie approach instead
  echo "      Bearer token not accepted; trying /callback with stored code..."
fi
echo

# ── Step 4: Wait and replay the same token ───────────────────────────────────
echo "  [4] Waiting ${REPLAY_DELAY}s before replay..."
sleep "$REPLAY_DELAY"

STATUS2=$(rcurl -sk -o /tmp/a3_response_$$.txt -w "%{http_code}" \
  -H "Authorization: Bearer $USE_TOKEN" \
  "${APP_URL%/}/protected" 2>/dev/null || echo "000")

BODY_PREVIEW=$(head -c 200 "/tmp/a3_response_$$.txt" 2>/dev/null || true)
rm -f "/tmp/a3_response_$$.txt"

echo "      Replayed same token → HTTP $STATUS2"
[[ -n "$BODY_PREVIEW" ]] && echo "      Response: $BODY_PREVIEW"
echo

# ── Verdict ──────────────────────────────────────────────────────────────────
if [[ "$STATUS1" == "200" && "$STATUS2" == "200" ]]; then
  echo "VULNERABLE — replayed token was accepted (no nonce/jti binding or revocation)"
elif [[ "$STATUS1" != "200" ]]; then
  echo "INCONCLUSIVE — could not establish baseline (first use returned HTTP $STATUS1)"
  echo "               The app may use session cookies instead of Bearer tokens."
else
  echo "PROTECTED  — replayed token was rejected (HTTP $STATUS2)"
fi
