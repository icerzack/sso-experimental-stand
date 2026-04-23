#!/bin/bash

# Collect Metrics Script
# Exports metrics from Prometheus for analysis

set -e

PROMETHEUS_URL="${PROMETHEUS_URL:-http://localhost:9090}"
OUTPUT_DIR="${OUTPUT_DIR:-./metrics-export}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$OUTPUT_DIR"

echo "=== Collecting Metrics from Prometheus ==="
echo "Prometheus URL: $PROMETHEUS_URL"
echo "Output directory: $OUTPUT_DIR"
echo ""

# Query metrics
queries=(
    "sso_login_duration_seconds"
    "sso_redirect_count"
    "sso_login_attempts_total"
    "sso_login_errors_total"
    "sso_login_success_total"
    "sso_active_sessions"
    "sso_session_access_duration_seconds"
    "sso_request_duration_seconds"
)

for query in "${queries[@]}"; do
    echo "Querying: $query"
    curl -s -G "$PROMETHEUS_URL/api/v1/query" \
        --data-urlencode "query=$query" \
        > "$OUTPUT_DIR/${query}_${TIMESTAMP}.json"
done

# Query range metrics (last 1 hour)
echo ""
echo "Querying range metrics (last 1 hour)..."
for query in "${queries[@]}"; do
    echo "Querying range: $query"
    curl -s -G "$PROMETHEUS_URL/api/v1/query_range" \
        --data-urlencode "query=$query" \
        --data-urlencode "start=$(date -d '1 hour ago' +%s)" \
        --data-urlencode "end=$(date +%s)" \
        --data-urlencode "step=15s" \
        > "$OUTPUT_DIR/${query}_range_${TIMESTAMP}.json"
done

# Export all metrics
echo ""
echo "Exporting all metrics..."
curl -s "$PROMETHEUS_URL/api/v1/label/__name__/values" > "$OUTPUT_DIR/all_metrics_${TIMESTAMP}.json"

echo ""
echo "=== Metrics Collection Complete ==="
echo "Files saved to: $OUTPUT_DIR"
echo "Timestamp: $TIMESTAMP"

