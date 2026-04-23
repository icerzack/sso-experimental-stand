#!/usr/bin/env bash

# Collect docker stats periodically and write as JSONL.
#
# Usage:
#   collect_docker_stats.sh <output_jsonl> <interval_s> <container_name> [container_name...]
#

set -euo pipefail

if [[ $# -lt 3 ]]; then
  echo "Usage: $0 <output_jsonl> <interval_s> <container_name> [container_name...]" >&2
  exit 2
fi

OUT="$1"
INTERVAL_S="$2"
shift 2
CONTAINERS=("$@")

mkdir -p "$(dirname "$OUT")"

stop_requested=0
trap 'stop_requested=1' INT TERM

now_rfc3339() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

while [[ $stop_requested -eq 0 ]]; do
  ts="$(now_rfc3339)"
  for c in "${CONTAINERS[@]}"; do
    # Example output:
    # 12.34%|123.4MiB / 1GiB|0.0%|1.23kB / 4.56kB
    line="$(docker stats --no-stream --format '{{.CPUPerc}}|{{.MemUsage}}|{{.MemPerc}}|{{.NetIO}}' "$c" 2>/dev/null || true)"
    if [[ -z "$line" ]]; then
      continue
    fi
    python3 - <<PY >>"$OUT"
import json
ts = ${ts!r}
container = ${c!r}
cpu_perc, mem_usage, mem_perc, net_io = ${line!r}.split("|", 3)
print(json.dumps({
  "timestamp": ts,
  "container": container,
  "cpu_perc": cpu_perc.strip(),
  "mem_usage": mem_usage.strip(),
  "mem_perc": mem_perc.strip(),
  "net_io": net_io.strip(),
}))
PY
  done
  sleep "$INTERVAL_S"
done


