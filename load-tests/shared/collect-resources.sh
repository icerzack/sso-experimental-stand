#!/bin/bash
# ============================================================================
# collect-resources.sh — Collect Docker container CPU/RAM metrics over time
# ============================================================================
# Usage:
#   ./shared/collect-resources.sh <container_name> <duration_seconds> <output_file>
#
# Example:
#   ./shared/collect-resources.sh sso-lab-idp 90 /tmp/resources_idp_100vu.csv
#
# Output format: CSV with columns:
#   timestamp,cpu_percent,ram_mb,ram_limit_mb,net_in_kb,net_out_kb
# ============================================================================

set -euo pipefail

CONTAINER="${1:?Usage: collect-resources.sh <container> <duration_s> <output_csv>}"
DURATION="${2:-90}"
OUTPUT="${3:-/tmp/resources_${CONTAINER}.csv}"

DOCKER="/usr/local/bin/docker"

echo "timestamp,cpu_percent,ram_mb,ram_limit_mb" > "$OUTPUT"

echo "Collecting resources for $CONTAINER for ${DURATION}s → $OUTPUT"

START=$(date +%s)
while [ $(($(date +%s) - START)) -lt "$DURATION" ]; do
  STATS=$($DOCKER stats --no-stream --format "{{.CPUPerc}}|{{.MemUsage}}" "$CONTAINER" 2>/dev/null || echo "0.00%|0MiB / 0MiB")
  
  # Parse CPU %
  CPU=$(echo "$STATS" | cut -d'|' -f1 | tr -d '%' | awk '{printf "%.1f", $1}')
  
  # Parse Memory: "123.4MiB / 16384MiB"
  MEM_PART=$(echo "$STATS" | cut -d'|' -f2)
  
  RAM_USED=$(echo "$MEM_PART" | awk '{print $1}' | sed \
    -e 's/GiB/*1024/' \
    -e 's/MiB//g' \
    -e 's/KiB/\/1024/' | bc 2>/dev/null || echo "0")
    
  RAM_LIMIT=$(echo "$MEM_PART" | awk -F'/' '{print $2}' | sed \
    -e 's/GiB/*1024/' \
    -e 's/MiB//g' \
    -e 's/KiB/\/1024/' | bc 2>/dev/null || echo "0")

  TIMESTAMP=$(date +"%H:%M:%S")
  echo "$TIMESTAMP,$CPU,$RAM_USED,$RAM_LIMIT" >> "$OUTPUT"
  
  sleep 3
done

echo "Done. Samples: $(wc -l < "$OUTPUT") lines in $OUTPUT"
echo "--- Summary ---"
awk -F',' 'NR>1 {cpu+=$3; mem+=$4; count++} END {
  printf "Avg CPU: %.1f%%\nAvg RAM: %.0f MB\nPeak RAM: %.0f MB\nSamples: %d\n",
    cpu/count, mem/count, mem, count
}' "$OUTPUT"
