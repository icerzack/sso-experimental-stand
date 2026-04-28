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

BASE_URL="${1:?Usage: $0 <base_url> <session_cookie>}"
SESSION="${2:-}"

if [[ -z "$SESSION" ]]; then
  echo "[A6] SKIPPED — session cookie is required for hijack replay test"
  exit 0
fi

PROTECTED="${BASE_URL%/}/protected"

echo "[A6] Session cookie hijack"
echo "     Target: $BASE_URL"
echo

# Step 1: check the Set-Cookie header to see what flags are present
HEADERS=$(curl -si "${BASE_URL%/}/" | grep -i "set-cookie" || true)
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
STATUS=$(curl -s -o /tmp/b3_response.txt -w "%{http_code}" \
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
