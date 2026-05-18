#!/bin/bash
set -e

BASE_URL="${1:-https://app.sso-lab.local}"
RESULTS_DIR="results/raw"
mkdir -p "$RESULTS_DIR"

echo "=== k6 Load Test ==="
echo "Target: $BASE_URL"
echo "Load mode: ${LOAD_MODE:-mixed}"

if ! command -v k6 &>/dev/null; then
    echo "k6 not found. Install: brew install k6 (macOS) or see https://k6.io/docs/get-started/installation/"
    exit 1
fi

# Staircase load: 10 → 50 → 100 → 200 virtual users
# Each step ramps up and holds, then ramps down.
# The k6 script handles the actual stage definitions internally
# based on VUS_START and VUS_PEAK env vars.

for VUS in 10 50 100 200; do
    echo ""
    echo "--- Running with $VUS virtual users (mode: ${LOAD_MODE:-mixed}) ---"

    # Build the k6 command with all required environment variables
    K6_CMD="k6 run"

    # Core connection params
    K6_CMD="$K6_CMD --env BASE_URL=$BASE_URL"
    K6_CMD="$K6_CMD --env IDP_URL=${IDP_URL:-https://idp.sso-lab.local}"
    K6_CMD="$K6_CMD --env REALM=${REALM:-sso-lab}"

    # Auth params
    K6_CMD="$K6_CMD --env CLIENT_ID=${CLIENT_ID:-sso-test-app}"
    K6_CMD="$K6_CMD --env CLIENT_SECRET=${CLIENT_SECRET:-testpass123}"
    K6_CMD="$K6_CMD --env TEST_USERNAME=${TEST_USERNAME:-testuser}"
    K6_CMD="$K6_CMD --env TEST_PASSWORD=${TEST_PASSWORD:-password123}"

    # Custom token URL override (for non-Keycloak IdPs)
    if [[ -n "${TOKEN_URL:-}" ]]; then
        K6_CMD="$K6_CMD --env TOKEN_URL=$TOKEN_URL"
    fi

    # Load shape
    K6_CMD="$K6_CMD --env VUS_START=$VUS"
    K6_CMD="$K6_CMD --env VUS_PEAK=$VUS"
    K6_CMD="$K6_CMD --env LOAD_MODE=${LOAD_MODE:-mixed}"

    # Output
    TIMESTAMP=$(date +%Y%m%d-%H%M%S)
    OUTFILE="$RESULTS_DIR/k6-${VUS}vu-${TIMESTAMP}.json"
    K6_CMD="$K6_CMD --out json=$OUTFILE"

    # Script
    K6_CMD="$K6_CMD k6/login-flow.js"

    eval "$K6_CMD" || {
        echo "WARNING: k6 exited with error at ${VUS} VU step. Continuing..."
    }

    # Brief pause between steps for metrics collection
    sleep 5
done

echo ""
echo "=== Load test complete. Results in $RESULTS_DIR/ ==="
ls -lt "$RESULTS_DIR"/k6-*.json 2>/dev/null | head -5 || true
