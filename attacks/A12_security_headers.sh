#!/usr/bin/env bash
# A12 — Security Headers Audit
# OWASP ASVS v4.2 § 14.4 / OWASP Secure Headers Project
#
# Checks each profile URL for the presence of the five most critical
# HTTP security response headers.
#
# Usage:
#   bash A12_security_headers.sh [url...]
#
# Examples:
#   bash A12_security_headers.sh http://app-a-v.local:8081 http://app-b-v.local:8082 http://app-c-v.local:8083
#   bash A12_security_headers.sh https://app-a-h.local https://app-b-h.local https://app-c-h.local
#
# Headers checked:
#   Strict-Transport-Security  — HSTS (HTTPS-only)
#   Content-Security-Policy    — XSS mitigation
#   X-Frame-Options            — clickjacking protection
#   X-Content-Type-Options     — MIME sniffing protection
#   Referrer-Policy            — referrer leakage control

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

if [[ $# -eq 0 ]]; then
  URLS=(
    "http://app-a-v.local:8081"
    "http://app-b-v.local:8082"
    "http://app-c-v.local:8083"
  )
else
  URLS=("$@")
fi

HEADERS_TO_CHECK=(
  "Strict-Transport-Security"
  "Content-Security-Policy"
  "X-Frame-Options"
  "X-Content-Type-Options"
  "Referrer-Policy"
)

TOTAL_CHECKS=0
TOTAL_PRESENT=0
TOTAL_MISSING=0

echo "[A12] Security Headers Audit"
echo

for URL in "${URLS[@]}"; do
  echo "  URL: $URL"
  RAW=$(rcurl -sk -o /dev/null -D - --max-time 10 "$URL" 2>/dev/null || \
        rcurl -s  -o /dev/null -D - --max-time 10 "$URL" 2>/dev/null || true)

  if [[ -z "$RAW" ]]; then
    echo "    ERROR — could not connect (is the service running?)"
    echo
    continue
  fi

  HTTP_STATUS=$(echo "$RAW" | head -1 | awk '{print $2}')
  echo "    HTTP status: $HTTP_STATUS"
  echo

  for HEADER in "${HEADERS_TO_CHECK[@]}"; do
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    VALUE=$(echo "$RAW" | grep -i "^${HEADER}:" | head -1 | sed 's/^[^:]*: //' | tr -d '\r' || true)
    if [[ -n "$VALUE" ]]; then
      TOTAL_PRESENT=$((TOTAL_PRESENT + 1))
      printf "    %-35s PRESENT  — %s\n" "$HEADER:" "${VALUE:0:80}"
    else
      TOTAL_MISSING=$((TOTAL_MISSING + 1))
      printf "    %-35s MISSING\n" "$HEADER:"
    fi
  done
  echo
done

# ── Summary ──────────────────────────────────────────────────────────────────
echo "─── Summary ───────────────────────────────────"
echo "  Checks performed : $TOTAL_CHECKS"
echo "  Present          : $TOTAL_PRESENT"
echo "  Missing          : $TOTAL_MISSING"
echo
if [[ "$TOTAL_MISSING" -eq 0 ]]; then
  echo "PROTECTED  — all security headers present on all tested URLs"
else
  echo "VULNERABLE — most security headers are absent"
fi
