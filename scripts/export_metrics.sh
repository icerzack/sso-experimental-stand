#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# export_metrics.sh — Export key metrics from Prometheus to JSON
#
# Queries Prometheus HTTP API for a given time range and saves
# results alongside k6 load test output.
#
# Usage:
#   ./scripts/export_metrics.sh [PROFILE] [START_EPOCH] [END_EPOCH]
#
#   PROFILE     — e2a/e2b/e2c/e2d (used in output filename)
#   START_EPOCH — Unix timestamp of measurement window start
#   END_EPOCH   — Unix timestamp of measurement window end
#
# If START/END not provided, uses last 5 minutes.
# Prometheus is expected at http://localhost:9090.
# ─────────────────────────────────────────────────────────────
set -euo pipefail

PROFILE="${1:-unknown}"
PROM_URL="${PROM_URL:-http://localhost:9090}"

if [[ -n "${2:-}" && -n "${3:-}" ]]; then
  START="$2"
  END="$3"
else
  END=$(date +%s)
  START=$((END - 300))  # last 5 minutes by default
fi

DURATION=$((END - START))

OUTDIR="results/raw"
mkdir -p "$OUTDIR"
OUTFILE="${OUTDIR}/prometheus-${PROFILE}-$(date +%Y%m%d-%H%M%S).json"

echo "=== Exporting Prometheus metrics ==="
echo "Profile:    $PROFILE"
echo "Time range: ${START} → ${END} (${DURATION}s window)"
echo "Output:     $OUTFILE"

# ── Helper: query Prometheus range API ──
query_range() {
  local query="$1"
  local step="${2:-15s}"
  curl --silent --max-time 10 \
    -G \
    --data-urlencode "query=${query}" \
    --data-urlencode "start=${START}" \
    --data-urlencode "end=${END}" \
    --data-urlencode "step=${step}" \
    "${PROM_URL}/api/v1/query_range" 2>/dev/null || echo '{"status":"error","data":{"result":[]}}'
}

# ── Helper: query Prometheus instant API ──
query_instant() {
  local query="$1"
  curl --silent --max-time 10 \
    -G \
    --data-urlencode "query=${query}" \
    --data-urlencode "time=${END}" \
    "${PROM_URL}/api/v1/query" 2>/dev/null || echo '{"status":"error","data":{"result":[]}}'
}

echo "Querying Prometheus..."

# Write all PromQL results to a temporary directory, then assemble JSON with Python.
TMPDIR_WORK="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_WORK"' EXIT

# 1. Request rate through Traefik (req/s)
query_range 'rate(traefik_entrypoint_requests_total{entrypoint="websecure"}[30s])' > "$TMPDIR_WORK/traffic_rate.json"

# 2. Latency percentiles through Traefik (seconds)
query_instant 'histogram_quantile(0.50, sum(rate(traefik_entrypoint_request_duration_seconds_bucket{entrypoint="websecure"}[2m])) by (le))' > "$TMPDIR_WORK/latency_p50.json"
query_instant 'histogram_quantile(0.95, sum(rate(traefik_entrypoint_request_duration_seconds_bucket{entrypoint="websecure"}[2m])) by (le))' > "$TMPDIR_WORK/latency_p95.json"
query_instant 'histogram_quantile(0.99, sum(rate(traefik_entrypoint_request_duration_seconds_bucket{entrypoint="websecure"}[2m])) by (le))' > "$TMPDIR_WORK/latency_p99.json"

# 3. Container CPU usage (%)
query_range 'rate(container_cpu_usage_seconds_total{name=~"sso-lab-idp.*"}[2m]) * 100' > "$TMPDIR_WORK/cpu_idp.json"
query_range 'rate(container_cpu_usage_seconds_total{name="sso-lab-app"}[2m]) * 100' > "$TMPDIR_WORK/cpu_app.json"

# 4. Container memory (MB) over time
query_range 'container_memory_working_set_bytes{name=~"sso-lab-idp.*"} / 1024 / 1024' > "$TMPDIR_WORK/mem_idp.json"
query_range 'container_memory_working_set_bytes{name="sso-lab-app"} / 1024 / 1024' > "$TMPDIR_WORK/mem_app.json"

# 5. Peak memory during the test window
query_instant "max_over_time(container_memory_working_set_bytes{name=~\"sso-lab-idp.*\"}[${DURATION}s]) / 1024 / 1024" > "$TMPDIR_WORK/peak_mem_idp.json"
query_instant "max_over_time(container_memory_working_set_bytes{name=\"sso-lab-app\"}[${DURATION}s]) / 1024 / 1024" > "$TMPDIR_WORK/peak_mem_app.json"

# 6. Total requests count in window
query_instant "sum(increase(traefik_entrypoint_requests_total{entrypoint=\"websecure\"}[${DURATION}s]))" > "$TMPDIR_WORK/total_requests.json"

# 7. Error rate (5xx responses)
query_instant 'sum(rate(traefik_entrypoint_requests_total{entrypoint="websecure",code=~"5.."}[2m])) / sum(rate(traefik_entrypoint_requests_total{entrypoint="websecure"}[2m]))' > "$TMPDIR_WORK/error_rate.json"

# 8. Keycloak-specific metrics (may be empty for non-Keycloak IdPs)
query_instant "sum(increase(keycloak_logins[${DURATION}s]))" > "$TMPDIR_WORK/keycloak_logins.json" 2>/dev/null || true

# ── Assemble final JSON with Python ──
python3 << 'PYEOF' "$TMPDIR_WORK" "$PROFILE" "$START" "$END" "$OUTFILE"
import json, sys, os

tmpdir = sys.argv[1]
profile = sys.argv[2]
start = int(sys.argv[3])
end = int(sys.argv[4])
outfile = sys.argv[5]

def safe_load(filename):
    path = os.path.join(tmpdir, filename)
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None

def extract_scalar(prom_result):
    """Extract a single scalar value from a Prometheus instant query result."""
    if not prom_result or prom_result.get("status") != "success":
        return None
    try:
        return float(prom_result["data"]["result"][0]["value"][1])
    except (IndexError, KeyError, ValueError, TypeError):
        return None

def extract_timeseries(prom_result):
    """Extract timeseries arrays from a Prometheus range query result."""
    if not prom_result or prom_result.get("status") != "success":
        return []
    series = []
    for r in prom_result.get("data", {}).get("result", []):
        metric = r.get("metric", {})
        values = r.get("values", [])
        series.append({
            "metric": metric,
            "values": [(int(v[0]), float(v[1])) for v in values],
        })
    return series

result = {
    "profile": profile,
    "time_window": {"start": start, "end": end, "duration_s": end - start},
    "summary": {
        "latency_p50_s": extract_scalar(safe_load("latency_p50.json")),
        "latency_p95_s": extract_scalar(safe_load("latency_p95.json")),
        "latency_p99_s": extract_scalar(safe_load("latency_p99.json")),
        "total_requests": extract_scalar(safe_load("total_requests.json")),
        "error_rate": extract_scalar(safe_load("error_rate.json")),
        "peak_mem_idp_mb": extract_scalar(safe_load("peak_mem_idp.json")),
        "peak_mem_app_mb": extract_scalar(safe_load("peak_mem_app.json")),
    },
    "timeseries": {
        "traffic_rate": extract_timeseries(safe_load("traffic_rate.json")),
        "cpu_idp_percent": extract_timeseries(safe_load("cpu_idp.json")),
        "cpu_app_percent": extract_timeseries(safe_load("cpu_app.json")),
        "mem_idp_mb": extract_timeseries(safe_load("mem_idp.json")),
        "mem_app_mb": extract_timeseries(safe_load("mem_app.json")),
    },
    "raw": {},
}
# Include keycloak data if present
kc = safe_load("keycloak_logins.json")
if kc and kc.get("status") == "success":
    result["raw"]["keycloak_logins"] = kc

with open(outfile, "w") as f:
    json.dump(result, f, indent=2, ensure_ascii=False)

print(f"Assembled {len(json.dumps(result))} bytes → {outfile}")
PYEOF

echo "Done."
