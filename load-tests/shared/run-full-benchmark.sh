#!/bin/bash
# ============================================================================
# run-full-benchmark.sh — Full benchmark suite for a single profile
# ============================================================================
# Runs: load tests (10/50/100/200 VU) + resource collection + startup measurement
#
# Usage:
#   ./shared/run-full-benchmark.sh <profile_dir>
#
# Example:
#   ./shared/run-full-benchmark.sh profiles/A_keycloak
#   ./shared/run-full-benchmark.sh profiles/B_authentik
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

PROFILE="${1:?Usage: run-full-benchmark.sh <profile_dir>}"

# Resolve profile path
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
  exit 1
fi

source "$CONFIG_FILE"

echo "╔══════════════════════════════════════════════════╗"
echo "║  FULL BENCHMARK SUITE                            ║"
echo "║  Profile: $PROFILE_NAME"
echo "║  IdP:     ${BASE_URL}"
echo "║  Container: ${CONTAINER_NAME}"
echo "╚══════════════════════════════════════════════════╝"

RESULTS_DIR="$BASE_DIR/results/$PROFILE_NAME"
mkdir -p "$RESULTS_DIR"

# --- Step 0: Verify IdP is reachable ---
echo ""
echo "[0/5] Verifying IdP connectivity..."
HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" "${BASE_URL}" 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "000" ]; then
  echo "ERROR: Cannot reach $BASE_URL. Is the IdP running?"
  exit 1
fi
echo "IdP is reachable (HTTP $HTTP_CODE)"

# --- Step 1: Collect idle resource usage ---
echo ""
echo "[1/5] Collecting idle resource metrics..."
DOCKER="/usr/local/bin/docker"
IDLE_STATS=$($DOCKER stats --no-stream --format "{{.CPUPerc}}|{{.MemUsage}}" "$CONTAINER_NAME" 2>/dev/null)
IDLE_CPU=$(echo "$IDLE_STATS" | cut -d'|' -f1)
IDLE_RAM=$(echo "$IDLE_STATS" | cut -d'|' -f2 | awk '{print $1}')
echo "Idle CPU: $IDLE_CPU, Idle RAM: $IDLE_RAM"
echo "idle_cpu=$IDLE_CPU" > "$RESULTS_DIR/idle_resources.env"
echo "idle_ram=$IDLE_RAM" >> "$RESULTS_DIR/idle_resources.env"

# --- Step 2: Run load tests at each VU level ---
for VU in 10 50 100; do
  echo ""
  echo "[2/5] Running load test at ${VU} VU..."
  
  # Start resource collection in background
  "$SCRIPT_DIR/collect-resources.sh" "$CONTAINER_NAME" 90 "$RESULTS_DIR/resources_${VU}vu.csv" &
  RES_PID=$!
  
  # Run load test
  "$SCRIPT_DIR/run-load-test.sh" "$PROFILE_DIR" "$VU" 60s
  
  wait $RES_PID 2>/dev/null || true
done

# 200 VU — longer test, more resources
echo ""
echo "[2/5] Running load test at 200 VU..."
"$SCRIPT_DIR/collect-resources.sh" "$CONTAINER_NAME" 120 "$RESULTS_DIR/resources_200vu.csv" &
RES_PID=$!

"$SCRIPT_DIR/run-load-test.sh" "$PROFILE_DIR" 200 60s
wait $RES_PID 2>/dev/null || true

# --- Step 3: Measure startup/recovery time ---
echo ""
echo "[3/5] Measuring startup and recovery time..."

TOKEN_URL="${TOKEN_URL:-}"
TOKEN_POST="${TOKEN_POST:-}"

"$SCRIPT_DIR/measure-startup.sh" "$CONTAINER_NAME" "$TOKEN_URL" "$TOKEN_POST" \
  | tee "$RESULTS_DIR/startup_measurements.txt"

# --- Step 4: Compile results ---
echo ""
echo "[4/5] Compiling results..."
OUTPUT="$RESULTS_DIR/benchmark_summary.txt"

{
  echo "=============================================="
  echo "  BENCHMARK SUMMARY: $PROFILE_NAME"
  echo "=============================================="
  echo ""
  echo "--- Login Latency (ms) ---"
  printf "%-6s %8s %8s %8s\n" "VU" "P50" "P95" "P99"
  
  for VU in 10 50 100 200; do
    JSON="$BASE_DIR/results/${PROFILE_NAME}_${VU}vu.json"
    if [ -f "$JSON" ]; then
      LATENCIES=$(grep '"metric":"login_latency"' "$JSON" | grep -o '"value":[0-9.]*' | cut -d: -f2 | sort -n)
      if [ -n "$LATENCIES" ]; then
        P50=$(echo "$LATENCIES" | awk 'BEGIN{c=0}{a[c++]=$1}END{printf "%d",a[int(c*0.50)]}')
        P95=$(echo "$LATENCIES" | awk 'BEGIN{c=0}{a[c++]=$1}END{printf "%d",a[int(c*0.95)]}')
        P99=$(echo "$LATENCIES" | awk 'BEGIN{c=0}{a[c++]=$1}END{printf "%d",a[int(c*0.99)]}')
        printf "%-6s %8s %8s %8s\n" "$VU" "$P50" "$P95" "$P99"
      fi
    fi
  done
  
  echo ""
  echo "--- Error Rate (%) ---"
  printf "%-6s %8s\n" "VU" "Error%"
  for VU in 10 50 100 200; do
    JSON="$BASE_DIR/results/${PROFILE_NAME}_${VU}vu.json"
    if [ -f "$JSON" ]; then
      TOTAL=$(grep -c '"metric":"errors"' "$JSON" 2>/dev/null || echo "0")
      ERRS=$(grep '"metric":"errors"' "$JSON" 2>/dev/null | grep -c '"value":1' || echo "0")
      if [ "$TOTAL" -gt 0 ] && [ "$ERRS" -gt 0 ]; then
        RATE=$(echo "scale=1; $ERRS * 100 / $TOTAL" | bc)
      else
        RATE="0.0"
      fi
      printf "%-6s %8s\n" "$VU" "$RATE"
    fi
  done
  
  echo ""
  echo "--- Resource Usage ---"
  source "$RESULTS_DIR/idle_resources.env" 2>/dev/null || true
  echo "Idle CPU: ${idle_cpu:-N/A}"
  echo "Idle RAM: ${idle_ram:-N/A}"
  
  # Peak resources under 100 VU from CSV
  if [ -f "$RESULTS_DIR/resources_100vu.csv" ]; then
    PEAK_CPU=$(awk -F',' 'NR>1 && $3+0>max {max=$3+0} END {printf "%.0f%%\n", max}' "$RESULTS_DIR/resources_100vu.csv")
    AVG_RAM=$(awk -F',' 'NR>1{s+=$4;n++}END{printf "%.0f MB\n", s/n}' "$RESULTS_DIR/resources_100vu.csv")
    PEAK_RAM=$(awk -F',' 'NR>1 && $4+0>max {max=$4+0} END {printf "%.0f MB\n", max}' "$RESULTS_DIR/resources_100vu.csv")
    echo "CPU peak @100 VU: $PEAK_CPU"
    echo "RAM avg @100 VU:  $AVG_RAM"
    echo "RAM peak @100 VU: $PEAK_RAM"
  fi
  
  echo ""
  echo "--- Startup/Recovery ---"
  grep -E '(startup|recovery|first login):' "$RESULTS_DIR/startup_measurements.txt" 2>/dev/null || echo "(see startup_measurements.txt)"
  
} | tee "$OUTPUT"

echo ""
echo "[5/5] Complete! Results saved to:"
echo "  $RESULTS_DIR/"
ls -la "$RESULTS_DIR/"

echo ""
echo "Full summary: $OUTPUT"
