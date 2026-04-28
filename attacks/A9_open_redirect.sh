#!/usr/bin/env bash
# A9 — Open Redirect via Post-Login ?next= (Domain Confusion)
# OWASP ASVS v4.2 § 5.1.5 — Validate redirect targets
# CWE-601 — URL Redirection to Untrusted Site
#
# The vulnerable apps validate ?next= with strings.Contains, allowing:
#   next=https://app-a-v.local.evil.com  →  passes (contains "app-a-v.local")
#   next=https://app-a-v.local           →  passes (legitimate)
#
# The hardened apps accept only relative paths (/foo) and reject all
# absolute URLs, so the bypass is impossible regardless of the hostname.
#
# Usage:
#   bash A9_open_redirect.sh <app_url> [allowed_domain]
#
# Examples:
#   bash A9_open_redirect.sh http://app-a-v.local:8081 app-a-v.local
#   bash A9_open_redirect.sh https://app-a-h.local     app-a-h.local
#   bash A9_open_redirect.sh http://app-b-v.local:8082 app-b-v.local

set -euo pipefail

APP_URL="${1:?Usage: $0 <app_url> [allowed_domain]}"
ALLOWED="${2:-app-a-v.local}"

# The evil domain embeds the allowed domain as a prefix substring.
EVIL_HOST="${ALLOWED}.evil.com"
EVIL_NEXT="https://${EVIL_HOST}/steal"
LEGIT_NEXT="https://${ALLOWED}/dashboard"

echo "[A9] Open Redirect — domain confusion via strings.Contains"
echo "     App:            $APP_URL"
echo "     Allowed domain: $ALLOWED"
echo "     Evil next:      $EVIL_NEXT"
echo

RESULTS=()

probe_redirect() {
  local label="$1" url="$2"
  local out loc status
  out=$(curl -si --max-redirs 0 --connect-timeout 5 "$url" 2>/dev/null || true)
  status=$(echo "$out" | head -1 | awk '{print $2}')
  loc=$(echo "$out" | grep -i "^location:" | head -1 | tr -d '\r' | sed 's/^[Ll]ocation: //' || true)
  echo "  $label"
  echo "    HTTP $status"
  [[ -n "$loc" ]] && echo "    Location: $loc"
  echo "$loc"
}

# ── Test 1: evil domain that embeds allowed as substring ────────────────────
echo "  [Test 1] next = $EVIL_NEXT"
# Profile A: trigger via /login?next=...
# Profile B: trigger via /?next=...
LOC1=$(probe_redirect "  GET /login?next=$EVIL_NEXT" \
  "${APP_URL%/}/login?next=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$EVIL_NEXT")" \
  2>/dev/null || true)
echo

if echo "$LOC1" | grep -q "evil.com"; then
  echo "           VULNERABLE — app redirected to evil domain after auth"
  RESULTS+=("T1:VULNERABLE")
else
  echo "           PROTECTED  — evil domain rejected (Location: $LOC1)"
  RESULTS+=("T1:PROTECTED")
fi
echo

# ── Test 2: double-slash bypass (//<evil>) ──────────────────────────────────
echo "  [Test 2] next = //evil.com/steal  (protocol-relative)"
DOUBLE_SLASH_NEXT="//evil.com/steal"
LOC2=$(probe_redirect "  GET /login?next=$DOUBLE_SLASH_NEXT" \
  "${APP_URL%/}/login?next=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$DOUBLE_SLASH_NEXT")" \
  2>/dev/null || true)
echo

if echo "$LOC2" | grep -q "evil.com"; then
  echo "           VULNERABLE — protocol-relative redirect accepted"
  RESULTS+=("T2:VULNERABLE")
else
  echo "           PROTECTED  — protocol-relative redirect rejected"
  RESULTS+=("T2:PROTECTED")
fi
echo

# ── Test 3: legitimate relative path — must still work ──────────────────────
echo "  [Test 3] next = /dashboard  (legitimate relative path)"
LOC3=$(probe_redirect "  GET /login?next=/dashboard" \
  "${APP_URL%/}/login?next=%2Fdashboard" \
  2>/dev/null || true)
echo

# For this test we just report what happened; both variants should allow it
if echo "$LOC3" | grep -qE "^/|${APP_URL}"; then
  echo "           OK — relative redirect preserved"
  RESULTS+=("T3:OK")
else
  echo "           NOTE — relative redirect not observed (app may require auth first)"
  RESULTS+=("T3:NOTE")
fi
echo

# ── Summary ─────────────────────────────────────────────────────────────────
echo "─── Summary ───────────────────────────────────"
for r in "${RESULTS[@]}"; do echo "  $r"; done
echo
ANY_VULN=false
for r in "${RESULTS[@]}"; do [[ "$r" == *VULNERABLE* ]] && ANY_VULN=true; done
if $ANY_VULN; then
  echo "VULNERABLE — open redirect bypass succeeded (see above)"
else
  echo "PROTECTED  — all redirect checks passed"
fi
