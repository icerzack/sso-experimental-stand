#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# bench-e2.sh — Full Experiment 2 benchmark orchestrator
#
# Automates the complete E2 measurement cycle for one profile:
#   1. Deploy the profile (make up-e2?)
#   2. Wait for health checks / warm-up
#   3. Measure startup time (first successful login)
#   4. Run k6 load test
#   5. Export Prometheus metrics to JSON
#   6. Tear down the profile (make down-e2?)
#   7. Generate summary report
#
# Usage:
#   ./scripts/bench-e2.sh PROFILE [WARMUP_SECONDS] [K6_OPTIONS...]
#
# Examples:
#   ./scripts/bench-e2.sh e2a              # Keycloak, default warm-up
#   ./scripts/bench-e2.sh e2b 120          # Authentik, extra warm-up
#   ./scripts/bench-e2.sh e2a 60 VUS_PEAK=100 LOAD_MODE=ropc
#
# Output:
#   results/raw/prometheus-{profile}-{timestamp}.json
#   results/raw/k6-{timestamp}.json
#   results/raw/startup-{profile}-{timestamp}.txt
#
# Prerequisites:
#   - Docker Compose stack not running
#   - /etc/hosts configured (make hosts-add)
#   - k6 installed on host
# ─────────────────────────────────────────────────────────────
set -euo pipefail

# ── Configuration ──

PROFILE="${1:?Usage: $0 PROFILE [WARMUP_SEC] [K6_ENV...]}"
shift || true

WARMUP="${1:-60}"
# If second arg looks like a number, consume it; otherwise keep it for k6 env
if [[ "$WARMUP" =~ ^[0-9]+$ ]]; then
  shift || true
else
  WARMUP=60
fi

# Remaining args are passed as environment variables to k6
K6_ENV=("$@")

APP_URL="https://app.sso-lab.local"
IDP_URL="https://idp.sso-lab.local"
OUTDIR="results/raw"
mkdir -p "$OUTDIR"

TIMESTAMP=$(date +%Y%m%d-%H%M%S)

# Profile-specific defaults
case "$PROFILE" in
  e2a) REALM="sso-lab";    IDP_NAME="Keycloak";       EXPECTED_PORT="8080";;
  e2b) REALM="application"; IDP_NAME="Authentik";     EXPECTED_PORT="9000";;
  e2c) REALM="";           IDP_NAME="Zitadel";       EXPECTED_PORT="8080";;
  e2d) REALM="";           IDP_NAME="Authelia OIDC";  EXPECTED_PORT="9091";;
  *)   echo "ERROR: Unknown profile '$PROFILE'. Expected: e2a, e2b, e2c, e2d"; exit 1;;
esac

echo "╔══════════════════════════════════════════════════╗"
echo "║  Experiment 2 Benchmark                         ║"
echo "║  Profile:    $PROFILE ($IDP_NAME)"
echo "║  Warm-up:    ${WARMUP}s"
echo "║  Output dir: $OUTDIR"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# ── Step 0: Check prerequisites ──

echo "── Step 0: Checking prerequisites ──"

if ! command -v k6 &>/dev/null; then
  echo "ERROR: k6 is not installed. Install with: brew install k6"
  echo "       or see https://k6.io/docs/get-started/installation/"
  exit 1
fi

if ! command -v curl &>/dev/null; then
  echo "ERROR: curl is not installed."
  exit 1
fi

if ! command -v docker &>/dev/null; then
  echo "ERROR: docker is not installed."
  exit 1
fi

# Check that no sso-lab containers are running
if docker ps --filter "name=sso-lab" --format "{{.Names}}" | grep -q .; then
  echo "ERROR: sso-lab containers are already running. Run 'make down' first."
  docker ps --filter "name=sso-lab" --format "table {{.Names}}\t{{.Status}}"
  exit 1
fi

# Check /etc/hosts
for h in app.sso-lab.local idp.sso-lab.local; do
  if ! grep -qE "[[:space:]]${h}([[:space:]]|$)" /etc/hosts 2>/dev/null; then
    echo "WARNING: $h not found in /etc/hosts. Run 'make hosts-add' first."
  fi
done

echo "Prerequisites OK."
echo ""

# ── Step 1: Deploy profile ──

BENCH_START_EPOCH=$(date +%s)

echo "── Step 1: Deploying profile $PROFILE ──"
make "up-${PROFILE}"
echo ""

# ── Step 2: Warm-up & health check ──

echo "── Step 2: Waiting ${WARMUP}s for services to stabilize ──"
sleep "$WARMUP"

# Wait for app to be reachable
MAX_WAIT=120
WAITED=0
until curl -sk -o /dev/null -w "%{http_code}" "${APP_URL}/healthz" 2>/dev/null | grep -q "200"; do
  WAITED=$((WAITED + 5))
  if [[ $WAITED -ge $MAX_WAIT ]]; then
    echo "ERROR: App did not become healthy within ${MAX_WAIT}s."
    make "down-${PROFILE}" 2>/dev/null || true
    exit 1
  fi
  echo "  Waiting for app healthz... (${WAITED}s/${MAX_WAIT}s)"
  sleep 5
done
echo "App is healthy."

STARTUP_TIME=$(( $(date +%s) - BENCH_START_EPOCH ))
echo "Startup time: ${STARTUP_TIME}s from 'make up' to healthy app."

# Save startup time
cat > "${OUTDIR}/startup-${PROFILE}-${TIMESTAMP}.txt" <<EOF
profile=$PROFILE
idp_name=$IDP_NAME
start_epoch=$BENCH_START_EPOCH
warmup_seconds=$WARMUP
startup_seconds=$STARTUP_TIME
healthy_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
EOF

echo ""

# ── Step 3: Measure time-to-first-login ──

echo "── Step 3: Measuring time-to-first-login ──"

LOGIN_START=$(date +%s%3N)

case "$PROFILE" in
  e2a)
    # Keycloak
    TOKEN_URL="${IDP_URL}/realms/${REALM}/protocol/openid-connect/token"
    ;;
  e2b)
    # Authentik uses a different token endpoint path
    TOKEN_URL="${IDP_URL}/application/o/token/"
    ;;
  e2c)
    # Zitadel uses a different token endpoint path
    TOKEN_URL="${IDP_URL}/oauth/v2/token"
    ;;
  e2d)
    # Authelia OIDC provider mode
    TOKEN_URL="${IDP_URL}/api/oidc/token"
    ;;
esac

FIRST_LOGIN_OK=false
FIRST_LOGIN_STATUS=""
for attempt in 1 2 3 4 5; do
  RESPONSE=$(curl -sk -w "\n%{http_code}" \
    -X POST "$TOKEN_URL" \
    -d "grant_type=password&client_id=sso-test-app&client_secret=testpass123&username=testuser&password=password123&scope=openid+profile+email" \
    2>/dev/null || echo -e "\n000")

  HTTP_CODE=$(echo "$RESPONSE" | tail -1)
  BODY=$(echo "$RESPONSE" | sed '$d')

  if [[ "$HTTP_CODE" == "200" ]] && echo "$BODY" | python3 -c "import sys,json; json.load(sys.stdin).get('access_token')" 2>/dev/null; then
    FIRST_LOGIN_OK=true
    break
  fi
  sleep 5
done

LOGIN_END=$(date +%s%3N)
LOGIN_DURATION_MS=$(( LOGIN_END - LOGIN_START ))

if [[ "$FIRST_LOGIN_OK" == true ]]; then
  echo "First login successful in ${LOGIN_DURATION_MS}ms"
else
  echo "WARNING: Could not achieve first login (HTTP $HTTP_CODE). Continuing anyway..."
  echo "Response body: $(echo "$BODY" | head -c 200)"
fi

# Append to startup file
{
  echo "first_login_ms=$LOGIN_DURATION_MS"
  echo "first_login_ok=$FIRST_LOGIN_OK"
} >> "${OUTDIR}/startup-${PROFILE}-${TIMESTAMP}.txt"

echo ""

# ── Step 4: Let Prometheus collect baseline ──

echo "── Step 4: Collecting baseline metrics (30s idle) ──"
BASELINE_START=$(date +%s)
sleep 30

echo ""

# ── Step 5: Run k6 load test ──

LOAD_START=$(date +%s)

echo "── Step 5: Running k6 load test ──"

# Build k6 environment variables
export BASE_URL="$APP_URL"
export IDP_URL="$IDP_URL"
export REALM="$REALM"
export CLIENT_ID="sso-test-app"
export CLIENT_SECRET="testpass123"
export TEST_USERNAME="testuser"
export TEST_PASSWORD="password123"

# Apply any user-provided k6 env overrides
for env_var in "${K6_ENV[@]}"; do
  export "$env_var"
done

bash k6/run.sh "$APP_URL" || {
  echo "WARNING: k6 load test exited with error. Metrics may be incomplete."
}

LOAD_END=$(date +%s)
echo "Load test completed in $(( LOAD_END - LOAD_START ))s."
echo ""

# ── Step 6: Cool-down + export Prometheus metrics ──

echo "── Step 6: Cooling down (10s) and exporting Prometheus metrics ──"
sleep 10

METRICS_END=$(date +%s)

bash scripts/export_metrics.sh "$PROFILE" "$BASELINE_START" "$METRICS_END"

echo ""

# ── Step 7: Tear down ──

echo "── Step 7: Tearing down profile $PROFILE ──"
make "down-${PROFILE}"

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  Benchmark Complete                              ║"
echo "║                                                  ║"
echo "║  Profile:      $PROFILE ($IDP_NAME)"
echo "║  Startup:      ${STARTUP_TIME}s"
echo "║  First login:  ${LOGIN_DURATION_MS}ms"
echo "║  Load window:  $(( LOAD_END - LOAD_START ))s"
echo "║                                                  ║"
echo "║  Results saved to:" 
ls -la "${OUTDIR}/"*"${TIMESTAMP}"* 2>/dev/null || ls -lt "${OUTDIR}/" | head -5
echo "╚══════════════════════════════════════════════════╝"
