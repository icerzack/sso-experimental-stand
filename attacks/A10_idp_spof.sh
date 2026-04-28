#!/usr/bin/env bash
# A10 — IdP Single Point of Failure
# OWASP ASVS v4.2 § 9.2.2 / MITRE ATT&CK T1499
#
# Stops the Keycloak container (or the entire IdP service) and verifies
# whether each application profile degrades gracefully or becomes
# completely unavailable (SPOF).
#
# Usage:
#   bash A10_idp_spof.sh [profile_a_url] [profile_b_url] [kc_container]
#
# Examples:
#   bash A10_idp_spof.sh http://app-a-v.local:8081 http://app-b-v.local:8082 profile-a-vuln-keycloak
#   bash A10_idp_spof.sh https://app-a-h.local     https://app-b-h.local     profile-a-hard-keycloak
#
# Result:
#   SPOF      — profile returned 5xx / connection refused when IdP is down
#   RESILIENT — profile served a response without the IdP (degraded mode)

set -euo pipefail

APP_A="${1:-http://app-a-v.local:8081}"
APP_B="${2:-http://app-b-v.local:8082}"
KC_CONTAINER="${3:-profile-a-vuln-keycloak}"

echo "[A10] IdP Single-Point-of-Failure test"
echo "     Keycloak container: ${KC_CONTAINER:-not-detected}"
echo "     Profile A:          $APP_A"
echo "     Profile B:          $APP_B"
echo

RESULTS=()

probe() {
  local label="$1" url="$2"
  local code
  if code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 10 "$url" 2>/dev/null); then
    :
  else
    code="000"
  fi
  echo "  $label → HTTP $code" >&2
  echo "$code"
}

detect_keycloak_container() {
  local candidate="$1"
  if docker ps --format '{{.Names}}' | grep -E -m1 "^${candidate}$" >/dev/null; then
    echo "$candidate"
    return
  fi
  docker ps --format '{{.Names}}' | grep -E -m1 "profile-a-.*keycloak|keycloak" || true
}

KC_CONTAINER="$(detect_keycloak_container "$KC_CONTAINER")"

# ── Baseline: verify apps respond before stopping IdP ───────────────────────
echo "  [Phase 1] Baseline — IdP running"
code_a_before=$(probe "Profile A /login (before)" "${APP_A%/}/login")
code_b_before=$(probe "Profile B /        (before)" "${APP_B%/}/")
echo

# ── Stop Keycloak ────────────────────────────────────────────────────────────
echo "  [Phase 2] Stopping container: $KC_CONTAINER"
if [[ -n "$KC_CONTAINER" ]] && docker stop "$KC_CONTAINER" >/dev/null 2>&1; then
  echo "           Container stopped."
else
  echo "           WARNING: could not stop container (not found or no Docker access)."
  echo "           Skipping live test — interpreting existing responses only."
fi
echo "           Waiting 5 s for propagation…"
sleep 5
echo

# ── Test while IdP is down ───────────────────────────────────────────────────
echo "  [Phase 3] Probing apps with IdP down"
code_a_down=$(probe "Profile A /login (IdP down)" "${APP_A%/}/login")
code_b_down=$(probe "Profile B /       (IdP down)" "${APP_B%/}/")
echo

classify() {
  local label="$1" code_before="$2" code_down="$3"
  if [[ "$code_down" =~ ^(000|502|503|504)$ ]]; then
    echo "  $label → SPOF (HTTP $code_down while IdP is down)"
    RESULTS+=("$label:SPOF")
  elif [[ "$code_down" =~ ^[23] ]]; then
    echo "  $label → RESILIENT (HTTP $code_down — served without IdP)"
    RESULTS+=("$label:RESILIENT")
  else
    echo "  $label → SPOF (HTTP $code_down)"
    RESULTS+=("$label:SPOF")
  fi
}

classify "ProfileA" "$code_a_before" "$code_a_down"
classify "ProfileB" "$code_b_before" "$code_b_down"
echo

# ── Restart Keycloak ─────────────────────────────────────────────────────────
echo "  [Phase 4] Restarting container: $KC_CONTAINER"
if [[ -n "$KC_CONTAINER" ]] && docker start "$KC_CONTAINER" >/dev/null 2>&1; then
  echo "           Container started."
else
  echo "           WARNING: could not restart container."
fi
echo

# ── Summary ──────────────────────────────────────────────────────────────────
echo "─── Summary ───────────────────────────────────"
for r in "${RESULTS[@]}"; do echo "  $r"; done
echo
ANY_SPOF=false
for r in "${RESULTS[@]}"; do [[ "$r" == *SPOF* ]] && ANY_SPOF=true; done
if $ANY_SPOF; then
  echo "SPOF DETECTED — one or more profiles became unavailable when the IdP stopped"
else
  echo "RESILIENT     — all profiles handled IdP downtime gracefully"
fi
