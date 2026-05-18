#!/bin/bash
# ============================================================================
# run-load-test.sh — Universal load test runner for OIDC login benchmark
# ============================================================================
# Usage:
#   ./shared/run-load-test.sh <profile_dir> [vu_level] [hold_duration]
#
# Example:
#   ./shared/run-load-test.sh profiles/A_keycloak 10 60s
#   ./shared/run-load-test.sh profiles/B_authentik 100 60s
#
# Prerequisites:
#   - k6 installed (/opt/homebrew/bin/k6)
#   - Profile directory must contain: config.env, oidc-login.js
#   - The IdP must be running and healthy
#
# Output:
#   - JSON results: results/<profile>_<vu>vu.json
#   - Console summary with percentiles
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

PROFILE="${1:?Usage: run-load-test.sh <profile_dir> [vu_level] [hold_duration]}"
TARGET_VU="${2:-}"
HOLD_DURATION="${3:-60s}"

# Resolve profile path (accept both short and full path)
if [ -d "$PROFILE" ]; then
  PROFILE_DIR="$(cd "$PROFILE" && pwd)"
else
  PROFILE_DIR="$BASE_DIR/profiles/$PROFILE"
fi

PROFILE_NAME=$(basename "$PROFILE_DIR")

# Load profile config
CONFIG_FILE="$PROFILE_DIR/config.env"
if [ ! -f "$CONFIG_FILE" ]; then
  echo "ERROR: config.env not found in $PROFILE_DIR"
  echo "Create one with: BASE_URL, APP_URL, CONTAINER_NAME, REALM, CLIENT_ID, CLIENT_SECRET, TEST_USER, TEST_PASSWORD"
  exit 1
fi

source "$CONFIG_FILE"

# Check k6 script exists
K6_SCRIPT="$PROFILE_DIR/oidc-login.js"
if [ ! -f "$K6_SCRIPT" ]; then
  echo "ERROR: oidc-login.js not found in $PROFILE_DIR"
  exit 1
fi

K6_BIN="${K6_BIN:-/opt/homebrew/bin/k6}"

# If no VU level specified, run all levels sequentially
if [ -z "$TARGET_VU" ]; then
  echo "=== Running all VU levels for $PROFILE_NAME ==="
  for VU in 10 50 100 200; do
    echo ""
    echo ">>> Starting ${VU} VU test..."
    "$0" "$PROFILE_DIR" "$VU" "$HOLD_DURATION"
  done
  echo ""
  echo "=== All tests completed for $PROFILE_NAME ==="
  exit 0
fi

OUTPUT_DIR="$BASE_DIR/results"
mkdir -p "$OUTPUT_DIR"

OUTPUT_FILE="$OUTPUT_DIR/${PROFILE_NAME}_${TARGET_VU}vu.json"

echo "╔════════════════════════════════════════════╗"
echo "║  Load Test: $PROFILE_NAME @ ${TARGET_VU} VU"
echo "║  Hold duration: $HOLD_DURATION"
echo "║  Base URL: ${BASE_URL}"
echo "║  Output: ${OUTPUT_FILE}"
echo "╚════════════════════════════════════════════╝"

K6_CMD="$K6_BIN run"
K6_CMD="$K6_CMD -e BASE_URL=$BASE_URL"
K6_CMD="$K6_CMD -e APP_URL=${APP_URL}"
K6_CMD="$K6_CMD -e TARGET_VU=$TARGET_VU"
K6_CMD="$K6_CMD -e HOLD_DURATION=$HOLD_DURATION"

# Pass auth configuration from profile config.env
[ -n "${CLIENT_ID:-}" ]      && K6_CMD="$K6_CMD -e CLIENT_ID=$CLIENT_ID"
[ -n "${CLIENT_SECRET:-}" ]   && K6_CMD="$K6_CMD -e CLIENT_SECRET=$CLIENT_SECRET"
[ -n "${TEST_USER:-}" ]       && K6_CMD="$K6_CMD -e TEST_USER=$TEST_USER"
[ -n "${TEST_PASSWORD:-}" ]    && K6_CMD="$K6_CMD -e TEST_PASSWORD=$TEST_PASSWORD"
[ -n "${REDIRECT_URI:-}" ]     && K6_CMD="$K6_CMD -e REDIRECT_URI=$REDIRECT_URI"
[ -n "${REALM:-}" ]            && K6_CMD="$K6_CMD -e REALM=$REALM"

K6_CMD="$K6_CMD --out json=$OUTPUT_FILE"
K6_CMD="$K6_CMD $K6_SCRIPT"

eval $K6_CMD

echo ""
echo "--- Results for ${TARGET_VU} VU ---"

# Parse results from the JSON output
LATENCIES=$(grep '"metric":"login_latency"' "$OUTPUT_FILE" | grep -o '"value":[0-9.]*' | cut -d: -f2 | sort -n)

if [ -n "$LATENCIES" ]; then
  COUNT=$(echo "$LATENCIES" | wc -l | tr -d ' ')
  
  P50=$(echo "$LATENCIES" | awk 'BEGIN{c=0}{a[c++]=$1}END{printf "%d",a[int(c*0.50)]}')
  P90=$(echo "$LATENCIES" | awk 'BEGIN{c=0}{a[c++]=$1}END{printf "%d",a[int(c*0.90)]}')
  P95=$(echo "$LATENCIES" | awk 'BEGIN{c=0}{a[c++]=$1}END{printf "%d",a[int(c*0.95)]}')
  P99=$(echo "$LATENCIES" | awk 'BEGIN{c=0}{a[c++]=$1}END{printf "%d",a[int(c*0.99)]}')
  AVG=$(echo "$LATENCIES" | awk '{s+=$1;n++}END{printf "%d",s/n}')
  
  TOTAL_ERR=$(grep -c '"metric":"errors"' "$OUTPUT_FILE" 2>/dev/null || echo "0")
  ERR_1=$(grep '"metric":"errors"' "$OUTPUT_FILE" 2>/dev/null | grep -c '"value":1' || echo "0")
  if [ "$TOTAL_ERR" -gt 0 ] && [ "$ERR_1" -gt 0 ]; then
    ERR_RATE=$(echo "scale=1; $ERR_1 * 100 / $TOTAL_ERR" | bc)
  else
    ERR_RATE="0.0"
  fi
  
  echo "  Iterations: $COUNT"
  echo "  Avg latency:  ${AVG} ms"
  echo "  P50 latency:  ${P50} ms"
  echo "  P90 latency:  ${P90} ms"
  echo "  P95 latency:  ${P95} ms"
  echo "  P99 latency:  ${P99} ms"
  echo "  Error rate:   ${ERR_RATE}%"
else
  echo "  WARNING: No latency data found!"
fi
