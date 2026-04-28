#!/usr/bin/env bash
# A4 — Token / Session Replay After Logout
# OWASP ASVS v4.2 § 3.3.1 — Verify logout invalidates the session server-side.
# MITRE ATT&CK T1550.004
#
# Usage:
#   bash A4_token_replay.sh <base_url> <session_cookie>
#
# Example (Profile A vulnerable):
#   # 1. Log in manually and copy the "sess" cookie value from DevTools
#   bash A4_token_replay.sh http://app-a-v.local:8081 "MTcz...base64..."
#
# Result:
#   VULNERABLE — /protected returned 200 after logout (session not invalidated)
#   PROTECTED  — /protected returned 401/302 after logout

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

BASE_URL="${1:?Usage: $0 <base_url> <session_cookie>}"
SESSION="${2:-}"

if [[ -z "$SESSION" ]]; then
  echo "[A4] SKIPPED — session cookie is required for replay test"
  exit 0
fi

PROTECTED="${BASE_URL%/}/protected"
LOGOUT="${BASE_URL%/}/logout"

echo "[A4] Token replay after logout"
echo "     Target: $BASE_URL"
echo "     Session: ${SESSION:0:20}…"
echo

# Step 1: verify session is valid before logout
STATUS_BEFORE=$(rcurl -s -o /dev/null -w "%{http_code}" \
  --cookie "sess=$SESSION" "$PROTECTED")
echo "  [1] /protected before logout → HTTP $STATUS_BEFORE"

if [[ "$STATUS_BEFORE" != "200" ]]; then
  echo
  echo "SKIPPED — session not valid before logout (got $STATUS_BEFORE). Provide a fresh session cookie."
  exit 0
fi

# Step 2: perform logout
STATUS_LOGOUT=$(rcurl -s -o /dev/null -w "%{http_code}" \
  -X POST --cookie "sess=$SESSION" "$LOGOUT")
echo "  [2] POST /logout             → HTTP $STATUS_LOGOUT"

# Step 3: replay the old session
STATUS_AFTER=$(rcurl -s -o /dev/null -w "%{http_code}" \
  --cookie "sess=$SESSION" "$PROTECTED")
echo "  [3] /protected after logout  → HTTP $STATUS_AFTER"

echo

if [[ "$STATUS_AFTER" == "200" ]]; then
  echo "VULNERABLE — old session still accepted after logout (HTTP $STATUS_AFTER)"
  echo "             Server does not maintain a revocation list or server-side session."
else
  echo "PROTECTED  — old session rejected after logout (HTTP $STATUS_AFTER)"
fi
