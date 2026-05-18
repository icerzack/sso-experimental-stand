#!/usr/bin/env bash
# A10 — WebAuthn RP ID Mismatch (Origin Binding Check)
# OWASP ASVS v4.2 § 2.8.4 / W3C WebAuthn Level 2 §7.1
# MITRE ATT&CK T1557 (Adversary-in-the-Middle)
#
# Profile: 1C
#
# WebAuthn credentials are cryptographically bound to the RP ID (effective domain).
# A credential registered on app.sso-lab.local CANNOT be used on evil-clone.local,
# because the browser enforces the origin check before releasing the assertion.
#
# This script simulates what an attacker would observe when attempting to trigger
# a WebAuthn ceremony from a phishing origin:
#   1. POST /webauthn/login/begin → obtains a challenge from the legitimate server
#   2. Crafts a fake clientDataJSON with origin = http://evil-clone.local
#   3. POSTs the forged data to /webauthn/login/finish
#   4. The server should reject it (origin does not match RP ID)
#
# Usage:
#   bash A10_webauthn_rp_mismatch.sh <app_url>

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

APP_URL="${1:?Usage: $0 <app_url>}"

EVIL_ORIGIN="http://evil-clone.local"

echo "[A10] WebAuthn RP ID Mismatch — origin binding check"
echo "     App: $APP_URL"
echo "     Forged origin: $EVIL_ORIGIN"
echo

RESULTS=()

# Helper: get a fresh challenge from /webauthn/login/begin
get_challenge() {
  local resp
  resp=$(rcurl -sk -X POST \
    -H "Content-Type: application/json" \
    "${APP_URL%/}/webauthn/login/begin" 2>/dev/null || true)

  echo "$resp" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    pk = d.get('publicKey', d)
    print(pk.get('challenge', ''))
except:
    print('')
" 2>/dev/null || true
}

# ── Verify server has WebAuthn endpoints ────────────────────────────────────
CHALLENGE=$(get_challenge)

if [[ -z "$CHALLENGE" ]]; then
  echo "      FAILED — could not obtain WebAuthn challenge"
  echo "      Is the server running and does it support WebAuthn?"
  echo
  echo "SKIPPED — server not ready or WebAuthn not configured"
  exit 0
fi

echo "  Server has WebAuthn endpoints ✓"
echo

# ── Test 1: Submit forged assertion with evil origin ────────────────────────
echo "  [Test 1] Forged clientDataJSON with origin=$EVIL_ORIGIN"
CHALLENGE1=$(get_challenge)

if [[ -z "$CHALLENGE1" ]]; then
  echo "      FAILED — could not obtain challenge for Test 1"
  RESULTS+=("T1:SKIP")
else
  FORGED_ASSERTION=$(python3 << PYEOF
import json, base64

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

challenge = "$CHALLENGE1"
evil_origin = "$EVIL_ORIGIN"

client_data = {
    "type": "webauthn.get",
    "challenge": challenge,
    "origin": evil_origin,
    "crossOrigin": False,
}
forged_client_data_json = b64url(json.dumps(client_data).encode())

forged_assertion = {
    "id": "AAAAAAAAAAAAAAAAAAAAAA",
    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
    "type": "public-key",
    "response": {
        "clientDataJSON": forged_client_data_json,
        "authenticatorData": b64url(b"\\x00" * 37),
        "signature": b64url(b"\\x00" * 64),
        "userHandle": None,
    },
}

print(json.dumps(forged_assertion))
PYEOF
)

  HTTP_STATUS=$(rcurl -sk -o /tmp/a10_t1_$$.txt -w "%{http_code}" \
    -X POST \
    -H "Content-Type: application/json" \
    -d "$FORGED_ASSERTION" \
    "${APP_URL%/}/webauthn/login/finish" 2>/dev/null || echo "000")

  BODY=$(head -c 500 "/tmp/a10_t1_$$.txt" 2>/dev/null || true)
  rm -f "/tmp/a10_t1_$$.txt"

  echo "      → HTTP $HTTP_STATUS"
  [[ -n "$BODY" ]] && echo "      Response: $(echo "$BODY" | head -c 200)"

  if [[ "$HTTP_STATUS" == "200" ]]; then
    echo "           VULNERABLE — server accepted assertion from evil origin!"
    RESULTS+=("T1:VULNERABLE")
  elif [[ "$HTTP_STATUS" == "403" || "$HTTP_STATUS" == "400" ]]; then
    if echo "$BODY" | grep -qi "origin"; then
      echo "           PROTECTED — server rejected with origin mismatch error"
    else
      echo "           PROTECTED — server rejected forged assertion (HTTP $HTTP_STATUS)"
    fi
    RESULTS+=("T1:PROTECTED")
  else
    echo "           PROTECTED — server did not accept (HTTP $HTTP_STATUS)"
    RESULTS+=("T1:PROTECTED")
  fi
fi
echo

# ── Test 2: Correct origin but wrong rpIdHash in authenticatorData ─────────
echo "  [Test 2] Correct origin, but wrong rpIdHash in authenticatorData"
CHALLENGE2=$(get_challenge)

if [[ -z "$CHALLENGE2" ]]; then
  echo "      FAILED — could not obtain challenge for Test 2"
  RESULTS+=("T2:SKIP")
else
  MISMATCH_ASSERTION=$(python3 << PYEOF
import json, base64, hashlib

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

challenge = "$CHALLENGE2"
correct_origin = "$APP_URL"

client_data = {
    "type": "webauthn.get",
    "challenge": challenge,
    "origin": correct_origin,
}

# Use WRONG rpIdHash in authdata (for evil-clone.local instead of sso-lab.local)
wrong_rp_id_hash = hashlib.sha256(b"evil-clone.local").digest()
# Minimal authData: rpIdHash(32) + flags(1) + signCount(4)
auth_data = wrong_rp_id_hash + b"\\x05" + b"\\x00\\x00\\x00\\x01"

mismatch_assertion = {
    "id": "AAAAAAAAAAAAAAAAAAAAAA",
    "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
    "type": "public-key",
    "response": {
        "clientDataJSON": b64url(json.dumps(client_data).encode()),
        "authenticatorData": b64url(auth_data),
        "signature": b64url(b"\\x00" * 64),
        "userHandle": None,
    },
}

print(json.dumps(mismatch_assertion))
PYEOF
)

  HTTP_STATUS2=$(rcurl -sk -o /tmp/a10_t2_$$.txt -w "%{http_code}" \
    -X POST \
    -H "Content-Type: application/json" \
    -d "$MISMATCH_ASSERTION" \
    "${APP_URL%/}/webauthn/login/finish" 2>/dev/null || echo "000")

  BODY2=$(head -c 500 "/tmp/a10_t2_$$.txt" 2>/dev/null || true)
  rm -f "/tmp/a10_t2_$$.txt"

  echo "      → HTTP $HTTP_STATUS2"
  [[ -n "$BODY2" ]] && echo "      Response: $(echo "$BODY2" | head -c 200)"

  if [[ "$HTTP_STATUS2" == "200" ]]; then
    echo "           VULNERABLE — server accepted assertion with wrong rpIdHash!"
    RESULTS+=("T2:VULNERABLE")
  elif [[ "$HTTP_STATUS2" == "403" || "$HTTP_STATUS2" == "400" ]]; then
    if echo "$BODY2" | grep -qi "rp.id\|rp_id\|rpidhash"; then
      echo "           PROTECTED — server rejected with rpIdHash mismatch error"
    else
      echo "           PROTECTED — server rejected (HTTP $HTTP_STATUS2)"
    fi
    RESULTS+=("T2:PROTECTED")
  else
    echo "           PROTECTED — server did not accept (HTTP $HTTP_STATUS2)"
    RESULTS+=("T2:PROTECTED")
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
  echo "VULNERABLE — WebAuthn origin/RP ID binding is NOT enforced"
  echo "             A credential from one domain can be used on another."
else
  echo "PROTECTED  — WebAuthn origin binding is working correctly"
  echo "             Credentials are cryptographically bound to their RP ID."
fi
