#!/usr/bin/env bash

# Run the full experiment matrix defined in experiments/config.yml.
#
# Prereqs: docker + docker compose, k6, curl, python3.
#
# Usage:
#   experiments/run_matrix.sh [path_to_config_yml]
#

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CFG="${1:-$ROOT_DIR/experiments/config.yml}"

if [[ ! -f "$CFG" ]]; then
  echo "Config not found: $CFG" >&2
  exit 2
fi

if ! command -v k6 >/dev/null 2>&1; then
  echo "ERROR: k6 is not installed (or not on PATH). This runner requires k6." >&2
  echo "" >&2
  echo "Install k6:" >&2
  echo "- macOS (Homebrew): brew install k6" >&2
  echo "- Linux (Debian/Ubuntu): see https://grafana.com/docs/k6/latest/set-up/install-k6/ (apt repo)" >&2
  echo "" >&2
  echo "After installing, re-run:" >&2
  echo "  ./experiments/run_matrix.sh" >&2
  exit 127
fi

yaml_scalar() {
  local key="$1"
  # Assumes: key: value (no quotes, no ':' in value)
  sed -nE "s/^${key}:[[:space:]]*(.+)$/\\1/p" "$CFG" | head -n 1 | tr -d '\r'
}

yaml_list() {
  local key="$1"
  # Assumes: key: [a, b, c]
  local raw
  raw="$(sed -nE "s/^${key}:[[:space:]]*\\[(.*)\\][[:space:]]*$/\\1/p" "$CFG" | head -n 1 | tr -d '\r')"
  if [[ -z "$raw" ]]; then
    return 0
  fi
  echo "$raw" | tr ',' '\n' | sed -E 's/^[[:space:]]+|[[:space:]]+$//g' | sed '/^$/d'
}

PROFILES=($(yaml_list "profiles"))
SCENARIOS=($(yaml_list "scenarios"))
CONCURRENCY=($(yaml_list "concurrency"))

WARM_UP_S="$(yaml_scalar "warm_up_s")"
STEADY_STATE_S="$(yaml_scalar "steady_state_s")"
REPEATS="$(yaml_scalar "repeats")"
SEED="$(yaml_scalar "seed")"

KEYCLOAK_URL="$(yaml_scalar "keycloak_url")"
APP_BASE="$(yaml_scalar "app_base_url")"

PROM_URL="$(yaml_scalar "prometheus_url")"
PROM_STEP="$(yaml_scalar "prometheus_step")"

USERNAME="$(yaml_scalar "username")"
PASSWORD="$(yaml_scalar "password")"
PASSKEY_USERNAME="$(yaml_scalar "passkey_username")"

RESULTS_RAW="$ROOT_DIR/results/raw"

url_host() {
  local url="$1"
  # Extract host part from http(s)://host[:port]/...
  echo "$url" | sed -E 's#^https?://([^/:]+).*$#\1#'
}

require_resolvable_host() {
  local name="$1"
  local host="$2"
  if [[ -z "$host" ]]; then
    return 0
  fi
  python3 - "$host" <<'PY' >/dev/null 2>&1
import socket
import sys
socket.gethostbyname(sys.argv[1])
PY
  if [[ $? -ne 0 ]]; then
    echo "ERROR: cannot resolve host for $name: $host" >&2
    echo "" >&2
    echo "Fix (recommended): add hosts entries:" >&2
    echo "  127.0.0.1 keycloak.localhost" >&2
    echo "  127.0.0.1 app.localhost" >&2
    echo "  127.0.0.1 vaultwarden.localhost" >&2
    echo "" >&2
    echo "On macOS/Linux:" >&2
    echo "  sudo sh -c 'printf \"127.0.0.1 keycloak.localhost\\n127.0.0.1 app.localhost\\n127.0.0.1 vaultwarden.localhost\\n\" >> /etc/hosts'" >&2
    exit 2
  fi
}

require_resolvable_host "KEYCLOAK_URL" "$(url_host "$KEYCLOAK_URL")"
require_resolvable_host "APP_BASE_URL" "$(url_host "$APP_BASE")"

run_id() {
  python3 - <<'PY'
import uuid
print(uuid.uuid4().hex)
PY
}

scenario_script() {
  local scenario="$1"
  case "$scenario" in
    cold) echo "$ROOT_DIR/k6/scripts/cold_login.js" ;;
    warm_idp) echo "$ROOT_DIR/k6/scripts/warm_login.js" ;;
    session_reuse) echo "$ROOT_DIR/k6/scripts/session_access.js" ;;
    logout_relogin) echo "$ROOT_DIR/k6/scripts/logout_relogin.js" ;;
    *) echo "" ;;
  esac
}

generate_matrix() {
  python3 - "$SEED" "$REPEATS" "$CFG" <<'PY'
import random, sys

seed = int(sys.argv[1])
repeats = int(sys.argv[2])
random.seed(seed)

def read_list(key):
  cfg = open(sys.argv[3], "r", encoding="utf-8").read().splitlines()
  for line in cfg:
    if line.startswith(key + ":"):
      if "[" in line and "]" in line:
        inner = line.split("[", 1)[1].split("]", 1)[0]
        return [x.strip() for x in inner.split(",") if x.strip()]
  return []

cfg_path = sys.argv[3]
profiles = read_list("profiles")
scenarios = read_list("scenarios")
concurrency = read_list("concurrency")

rows = []
for profile in profiles:
  for scenario in scenarios:
    for conc in concurrency:
      for rep in range(1, repeats + 1):
        rows.append((profile, scenario, int(conc), rep))

random.shuffle(rows)
for profile, scenario, conc, rep in rows:
  print(f"{profile},{scenario},{conc},{rep}")
PY
}

echo "=== Running experiment matrix ==="
echo "Config: $CFG"
echo "Matrix: profiles=${PROFILES[*]} scenarios=${SCENARIOS[*]} concurrency=${CONCURRENCY[*]} repeats=$REPEATS seed=$SEED"

echo ""
echo "Ensuring the stand is up..."
cd "$ROOT_DIR"
docker compose up -d

echo "Waiting for services to become healthy..."
docker compose ps

health_wait_deadline=$(( $(date +%s) + 15 ))
while [[ $(date +%s) -lt $health_wait_deadline ]]; do
  if docker compose ps --format json 2>/dev/null | python3 - <<'PY'
import json, sys
raw = sys.stdin.read().strip()
if not raw:
  sys.exit(1)
rows = json.loads(raw)
# Consider "running" without explicit healthcheck as OK, and "healthy" as OK.
ok = True
for r in rows:
  st = (r.get("State") or "").lower()
  health = (r.get("Health") or "").lower()
  if "exited" in st or "dead" in st:
    ok = False
  if health and health not in ("healthy",):
    ok = False
print("ok" if ok else "not_ok")
sys.exit(0 if ok else 2)
PY
  then
    echo "Services are running/healthy."
    break
  fi
  sleep 5
done

matrix_file="$(mktemp)"
generate_matrix >"$matrix_file"

while IFS=',' read -r profile scenario conc rep; do
  if [[ -z "${profile:-}" || -z "${scenario:-}" || -z "${conc:-}" || -z "${rep:-}" ]]; then
    continue
  fi

  script="$(scenario_script "$scenario")"
  base_url="$APP_BASE"

  if [[ -z "$script" || -z "$base_url" ]]; then
    echo "Skipping invalid matrix row: profile=$profile scenario=$scenario" >&2
    continue
  fi

  rid="$(run_id)"
  run_dir="$RESULTS_RAW/$rid"
  mkdir -p "$run_dir"

  echo ""
  echo "--- Run $rid: profile=$profile scenario=$scenario concurrency=$conc repeat=$rep ---"

  meta_path="$run_dir/run_metadata.json"
  docker_stats_path="$run_dir/docker_stats.jsonl"
  prom_dir="$run_dir/prometheus"

  "$ROOT_DIR/experiments/collect_run_metadata.sh" \
    "$meta_path" "$rid" "$profile" "$scenario" "$conc" "$rep" "$SEED" "$WARM_UP_S" "$STEADY_STATE_S" "$((WARM_UP_S + STEADY_STATE_S))"

  # Collect container image references (best-effort)
  docker inspect sso-keycloak sso-app sso-vaultwarden sso-postgres sso-prometheus sso-grafana sso-caddy >/dev/null 2>&1 || true
  docker ps --format '{{.Names}}|{{.Image}}|{{.ID}}' > "$run_dir/docker_containers.txt" 2>/dev/null || true

  # Start docker stats sampling in the background
  "$ROOT_DIR/experiments/collect_docker_stats.sh" "$docker_stats_path" 2 sso-keycloak sso-app sso-vaultwarden >/dev/null 2>&1 &
  stats_pid="$!"

  start_epoch="$(date +%s)"

  # Run k6 with per-run summary export.
  BASE_URL="$base_url" \
  KEYCLOAK_URL="$KEYCLOAK_URL" \
  PROFILE="$profile" \
  USERNAME="$USERNAME" \
  PASSWORD="$PASSWORD" \
  PASSKEY_USERNAME="$PASSKEY_USERNAME" \
  CONCURRENCY="$conc" \
  WARM_UP_S="$WARM_UP_S" \
  STEADY_STATE_S="$STEADY_STATE_S" \
  DISABLE_THRESHOLDS="1" \
  SUMMARY_PATH="$run_dir/k6_handle_summary.json" \
  k6 run "$script" --summary-export "$run_dir/k6_summary.json"

  end_epoch="$(date +%s)"

  # Stop docker stats sampler
  kill "$stats_pid" >/dev/null 2>&1 || true
  wait "$stats_pid" >/dev/null 2>&1 || true

  # Export Prometheus metrics for this exact window
  PROMETHEUS_URL="$PROM_URL" \
  "$ROOT_DIR/experiments/export_prometheus_run.sh" "$prom_dir" "$start_epoch" "$end_epoch" "$PROM_URL" "$PROM_STEP"

  # Finalize metadata with finish time and artifact pointers (best-effort)
  python3 - "$meta_path" "$rid" <<'PY'
import datetime
import json
import sys

path = sys.argv[1]
rid = sys.argv[2]

with open(path, "r", encoding="utf-8") as f:
  data = json.load(f)

data["finished_at"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
data.setdefault("artifacts", {})
data["artifacts"].update({
  "k6_summary_path": f"results/raw/{rid}/k6_summary.json",
  "prometheus_export_dir": f"results/raw/{rid}/prometheus",
  "docker_stats_path": f"results/raw/{rid}/docker_stats.jsonl",
})

with open(path, "w", encoding="utf-8") as f:
  json.dump(data, f, ensure_ascii=False, indent=2)
  f.write("\n")
PY
done <"$matrix_file"

rm -f "$matrix_file"

echo ""
echo "=== Matrix complete. Raw results in: $RESULTS_RAW ==="


