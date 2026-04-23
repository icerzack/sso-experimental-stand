#!/usr/bin/env bash

# Collect run metadata for reproducibility (OS/hardware/tool versions).
# This script is intended to be called by the experiment runner before and after each run.

set -euo pipefail

if [[ $# -lt 6 ]]; then
  echo "Usage: $0 <output_json> <run_id> <protocol> <scenario> <concurrency> <repeat_no> [seed] [warm_up_s] [steady_state_s] [duration_s]" >&2
  exit 2
fi

OUTPUT_JSON="$1"
RUN_ID="$2"
PROTOCOL="$3"
SCENARIO="$4"
CONCURRENCY="$5"
REPEAT_NO="$6"
SEED="${7:-}"
WARM_UP_S="${8:-}"
STEADY_STATE_S="${9:-}"
DURATION_S="${10:-}"

now_rfc3339() {
  # GNU date supports --iso-8601/--rfc-3339, but keep it portable
  if date -u +"%Y-%m-%dT%H:%M:%SZ" >/dev/null 2>&1; then
    date -u +"%Y-%m-%dT%H:%M:%SZ"
  else
    python3 - <<'PY'
from datetime import datetime, timezone
print(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
PY
  fi
}

get_git_commit() {
  git rev-parse HEAD 2>/dev/null || true
}

get_docker_version() {
  docker --version 2>/dev/null | tr -d '\n' || true
}

get_docker_compose_version() {
  docker compose version 2>/dev/null | tr -d '\n' || true
}

get_k6_version() {
  k6 version 2>/dev/null | head -n 1 | tr -d '\n' || true
}

get_os() {
  uname -s 2>/dev/null || true
}

get_kernel() {
  uname -r 2>/dev/null || true
}

get_cpu_model() {
  if command -v lscpu >/dev/null 2>&1; then
    lscpu | awk -F: '/Model name/ {gsub(/^[ \t]+/, "", $2); print $2; exit}'
  elif [[ "$(uname -s 2>/dev/null)" == "Darwin" ]]; then
    sysctl -n machdep.cpu.brand_string 2>/dev/null || true
  else
    true
  fi
}

get_cpu_cores() {
  if command -v nproc >/dev/null 2>&1; then
    nproc
  elif [[ "$(uname -s 2>/dev/null)" == "Darwin" ]]; then
    sysctl -n hw.ncpu 2>/dev/null || true
  else
    true
  fi
}

get_mem_total_mb() {
  if [[ -r /proc/meminfo ]]; then
    awk '/MemTotal/ {printf "%d\n", $2/1024; exit}' /proc/meminfo
  elif [[ "$(uname -s 2>/dev/null)" == "Darwin" ]]; then
    # bytes to MB
    python3 - <<'PY'
import subprocess, sys
try:
  out = subprocess.check_output(["sysctl", "-n", "hw.memsize"]).decode().strip()
  print(int(int(out)/1024/1024))
except Exception:
  pass
PY
  else
    true
  fi
}

STARTED_AT="$(now_rfc3339)"
GIT_COMMIT="$(get_git_commit)"
DOCKER_VERSION="$(get_docker_version)"
DOCKER_COMPOSE_VERSION="$(get_docker_compose_version)"
K6_VERSION="$(get_k6_version)"
OS_NAME="$(get_os)"
KERNEL="$(get_kernel)"
CPU_MODEL="$(get_cpu_model)"
CPU_CORES="$(get_cpu_cores)"
MEM_TOTAL_MB="$(get_mem_total_mb)"

mkdir -p "$(dirname "$OUTPUT_JSON")"

python3 - "$OUTPUT_JSON" "$RUN_ID" "$STARTED_AT" "$PROTOCOL" "$SCENARIO" "$CONCURRENCY" "$REPEAT_NO" "$SEED" "$WARM_UP_S" "$STEADY_STATE_S" "$DURATION_S" "$OS_NAME" "$KERNEL" "$CPU_MODEL" "$CPU_CORES" "$MEM_TOTAL_MB" "$GIT_COMMIT" "$DOCKER_VERSION" "$DOCKER_COMPOSE_VERSION" "$K6_VERSION" <<'PY'
import json
import sys

def maybe_int(x):
  if x is None:
    return None
  x = str(x).strip()
  if not x:
    return None
  try:
    return int(x)
  except Exception:
    return None

(
  output_json,
  run_id,
  started_at,
  protocol,
  scenario,
  concurrency,
  repeat_no,
  seed,
  warm_up_s,
  steady_state_s,
  duration_s,
  os_name,
  kernel,
  cpu_model,
  cpu_cores,
  mem_total_mb,
  git_commit,
  docker_version,
  docker_compose_version,
  k6_version,
) = sys.argv[1:21]

data = {
  "run_id": run_id,
  "started_at": started_at,
  "protocol": protocol,
  "scenario": scenario,
  "concurrency": maybe_int(concurrency) or 0,
  "repeat_no": maybe_int(repeat_no) or 0,
  "seed": maybe_int(seed),
  "warm_up_s": maybe_int(warm_up_s),
  "steady_state_s": maybe_int(steady_state_s),
  "duration_s": maybe_int(duration_s),
  "environment": {
    "os": os_name,
    "kernel": kernel,
    "cpu_model": cpu_model,
    "cpu_cores": maybe_int(cpu_cores),
    "memory_total_mb": maybe_int(mem_total_mb),
  },
  "versions": {
    "git_commit": git_commit,
    "docker_version": docker_version,
    "docker_compose_version": docker_compose_version,
    "k6_version": k6_version,
  },
}

with open(output_json, "w", encoding="utf-8") as f:
  json.dump(data, f, ensure_ascii=False, indent=2)
  f.write("\n")
PY


echo "Wrote run metadata: $OUTPUT_JSON"


