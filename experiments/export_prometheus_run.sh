#!/usr/bin/env bash

# Export Prometheus metrics for a single experiment run using an explicit time window.
#
# Usage:
#   export_prometheus_run.sh <output_dir> <start_epoch_s> <end_epoch_s> [prometheus_url] [step_s]
#
# Output:
#   - <output_dir>/instant/<metric>.json
#   - <output_dir>/range/<metric>.json
#

set -euo pipefail

if [[ $# -lt 3 ]]; then
  echo "Usage: $0 <output_dir> <start_epoch_s> <end_epoch_s> [prometheus_url] [step_s]" >&2
  exit 2
fi

OUT_DIR="$1"
START="$2"
END="$3"
PROM_URL="${4:-http://localhost:9090}"
STEP="${5:-5s}"

mkdir -p "$OUT_DIR/instant" "$OUT_DIR/range"

query_instant() {
  local name="$1"
  local q="$2"
  curl -s -G "$PROM_URL/api/v1/query" \
    --data-urlencode "query=$q" \
    > "$OUT_DIR/instant/${name}.json"
}

query_range() {
  local name="$1"
  local q="$2"
  curl -s -G "$PROM_URL/api/v1/query_range" \
    --data-urlencode "query=$q" \
    --data-urlencode "start=$START" \
    --data-urlencode "end=$END" \
    --data-urlencode "step=$STEP" \
    > "$OUT_DIR/range/${name}.json"
}

# App-level SSO metrics
query_instant "sso_login_attempts_total" "sso_login_attempts_total"
query_instant "sso_login_success_total" "sso_login_success_total"
query_instant "sso_login_errors_total" "sso_login_errors_total"
query_instant "sso_active_sessions" "sso_active_sessions"

query_range "sso_login_duration_seconds_bucket" "sso_login_duration_seconds_bucket"
query_range "sso_login_duration_seconds_sum" "sso_login_duration_seconds_sum"
query_range "sso_login_duration_seconds_count" "sso_login_duration_seconds_count"

query_range "sso_redirect_count_bucket" "sso_redirect_count_bucket"
query_range "sso_redirect_count_sum" "sso_redirect_count_sum"
query_range "sso_redirect_count_count" "sso_redirect_count_count"

query_range "sso_session_access_duration_seconds_bucket" "sso_session_access_duration_seconds_bucket"
query_range "sso_request_duration_seconds_bucket" "sso_request_duration_seconds_bucket"

# Protocol payload sizing (added by this experiment harness in the apps)
query_range "sso_protocol_payload_size_bytes_bucket" "sso_protocol_payload_size_bytes_bucket"
query_range "sso_protocol_payload_size_bytes_sum" "sso_protocol_payload_size_bytes_sum"
query_range "sso_protocol_payload_size_bytes_count" "sso_protocol_payload_size_bytes_count"

# Keycloak metrics (when enabled)
query_range "keycloak_process_cpu_seconds_total" "process_cpu_seconds_total{job=\"keycloak\"}"
query_range "keycloak_jvm_memory_used_bytes" "jvm_memory_used_bytes{job=\"keycloak\"}"

echo "Exported Prometheus metrics to: $OUT_DIR"


