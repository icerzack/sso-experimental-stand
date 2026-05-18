#!/bin/bash
# Collect resource usage metrics from Docker containers during load test.
# Usage: ./collect-resources.sh <container_name> <duration_seconds> <output_file>
#
# Output format: CSV with columns:
# timestamp,container,cpu_percent,mem_usage_mb,mem_limit_mb,mem_percent,net_in_kb,net_out_kb

set -euo pipefail

CONTAINER="${1:-sso-lab-idp}"
DURATION="${2:-90}"
OUTPUT="${3:-/tmp/resources_${CONTAINER}.csv}"

echo "timestamp,container,cpu_percent,mem_usage_mb,mem_limit_mb,mem_percent,net_in_kb,net_out_kb" > "$OUTPUT"

echo "Collecting metrics for $CONTAINER for ${DURATION}s → $OUTPUT"

START=$(date +%s)
while [ $(($(date +%s) - START)) -lt "$DURATION" ]; do
  STATS=$(docker stats --no-stream --format \
    "{{.CPUPerc}},{{.MemUsage}},{{.MemPerc}},{{.NetIO}}" \
    "$CONTAINER" 2>/dev/null || echo "0.00%,0MiB / 0MiB,0.00%,0B / 0B")

  # Parse CPU percent
  CPU=$(echo "$STATS" | awk -F',' '{print $1}' | tr -d '%')
  
  # Parse memory: "123.4MiB / 16384MiB"
  MEM_INFO=$(echo "$STATS" | awk -F',' '{print $2}')
  MEM_USAGE_MB=$(echo "$MEM_INFO" | awk '{print $1}' | sed 's/MiB//;s/GiB/*1024/' | bc 2>/dev/null || echo "0")
  MEM_LIMIT_MB=$(echo "$MEM_INFO" | awk -F'/' '{print $2}' | sed 's/MiB//;s/GiB/*1024/' | bc 2>/dev/null || echo "0")
  
  MEM_PCT=$(echo "$STATS" | awk -F',' '{print $3}' | tr -d '%')
  
  # Network IO: "1.23kB / 4.56kB"
  NET_INFO=$(echo "$STATS" | awk -F',' '{print $4}')
  NET_IN=$(echo "$NET_INFO" | awk '{print $1}' | sed 's/kB//;s/MB/*1024/' | bc 2>/dev/null || echo "0")
  NET_OUT=$(echo "$NET_INFO" | awk -F'/' '{print $2}' | sed 's/kB//;s/MB/*1024/' | bc 2>/dev/null || echo "0")

  TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  echo "$TIMESTAMP,$CONTAINER,$CPU,$MEM_USAGE_MB,$MEM_LIMIT_MB,$MEM_PCT,$NET_IN,$NET_OUT" >> "$OUTPUT"
  
  sleep 2
done

echo "Done. Results in $OUTPUT"
echo "--- Summary ---"
awk -F',' 'NR>1 {cpu+=$3; mem+=$4; count++} END {printf "Avg CPU: %.1f%%\nAvg RAM: %.0f MB\nSamples: %d\n", cpu/count, mem/count, count}' "$OUTPUT"
