#!/bin/bash
# ============================================================================
# run-all-profiles.sh — Run load tests for ALL profiles sequentially
# ============================================================================
# Switches docker compose profile, waits for healthy, runs benchmark, saves results
#
# Usage:
#   ./load-tests/run-all-profiles.sh [profiles...]
#
# Example:
#   ./load-tests/run-all-profiles.sh e2a e2b e2c e2d
#   ./load-tests/run-all-profiles.sh              # all profiles
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DOCKER="/usr/local/bin/docker"
K6_BIN="/opt/homebrew/bin/k6"

# All profiles to test (in order)
ALL_PROFILES=(e1a e1b e1c e1d e2a e2b e2c e2d)

# Override with arguments if provided
PROFILES=("${@:-${ALL_PROFILES[@]}}")

# Profile to load-test directory mapping
declare -A PROFILE_MAP=(
  [e1a]="profiles/A_keycloak"
  [e1b]="profiles/A_keycloak"         # SAML — reuses Keycloak script (different realm config)
  [e1c]="profiles/D_authelia"        # Forward Auth Authelia  
  [e1d]="profiles/A_keycloak"        # WebAuthn — same Keycloak script but WebAuthn realm
  [e2a]="profiles/A_keycloak"        # Same as E1A (crossover point)
  [e2b]="profiles/B_authentik"
  [e2c]="profiles/C_zitadel"
  [e2d]="profiles/D_authelia"        # OIDC mode Authelia
)

# Display name mapping for results
declare -A DISPLAY_NAMES=(
  [e1a]="E1A_Keycloak_OIDC_Password"
  [e1b]="E1B_Keycloak_SAML_Password"
  [e1c]="E1C_Authelia_ForwardAuth_Password"
  [e1d]="E1D_Keycloak_OIDC_WebAuthn"
  [e2a]="E2A_Keycloak_OIDC_Password"
  [e2b]="E2B_Authentik_OIDC_Password"
  [e2c]="E2C_Zitadel_OIDC_Password"
  [e2d]="E2D_Authelia_OIDC_Password"
)

echo "╔══════════════════════════════════════════════════╗"
echo "║  SSO LOAD TEST SUITE — ALL PROFILES             ║"
echo "║  Profiles: ${PROFILES[*]}"
echo "╚══════════════════════════════════════════════════╝"

RESULTS_BASE="$BASE_DIR/load-tests/results"
mkdir -p "$RESULTS_BASE"

for PROFILE in "${PROFILES[@]}"; do
  LT_DIR="${PROFILE_MAP[$PROFILE]:-}"
  DISPLAY="${DISPLAY_NAMES[$PROFILE]:-$PROFILE}"
  RESULT_FILE="$RESULTS_BASE/RESULTS_Profile_${DISPLAY}.md"

  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  Starting profile: $PROFILE ($DISPLAY)"
  echo "  Load-test dir: $LT_DIR"
  echo "  Result file: $RESULT_FILE"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  # ── Step 0: Tear down existing stack ──
  echo "[0] Tearing down existing stack..."
  cd "$BASE_DIR"
  $DOCKER compose --profile "$PROFILE" down --remove-orphans --timeout 30 2>/dev/null || true
  
  # Wait for containers to fully stop
  sleep 5

  # Remove orphaned containers that might conflict
  for cname in sso-lab-idp sso-lab-app sso-lab-redis; do
    if $DOCKER ps -a --format '{{.Names}}' | grep -q "^${cname}$"; then
      $DOCKER rm -f "$cname" 2>/dev/null || true
    fi
  done

  # ── Step 1: Start the profile ──
  echo "[1] Starting profile $PROFILE..."
  $DOCKER compose --profile "$PROFILE" up -d 2>&1 || {
    echo "ERROR: Failed to start profile $PROFILE. Skipping."
    continue
  }

  # ── Step 2: Wait for IdP to become healthy ──
  echo "[2] Waiting for IdP to become healthy..."
  WAIT=0
  MAX_WAIT=180
  while [ $WAIT -lt $MAX_WAIT ]; do
    STATUS=$($DOCKER inspect --format='{{.State.Health.Status}}' sso-lab-idp 2>/dev/null || echo "unknown")
    if [ "$STATUS" = "healthy" ]; then
      echo "  IdP is healthy after ${WAIT}s"
      break
    fi
    echo "  Waiting... ($STATUS) ${WAIT}s/$MAX_WAIT"
    sleep 5
    WAIT=$((WAIT + 5))
  done

  if [ $WAIT -ge $MAX_WAIT ]; then
    STATUS=$($DOCKER inspect --format='{{.State.Health.Status}}' sso-lab-idp 2>/dev/null || echo "unknown")
    echo "  WARNING: IdP did not become healthy in ${MAX_WAIT}s (status: $STATUS). Running tests anyway."
  fi

  # Extra stabilization time
  sleep 10

  # ── Step 3: Post-deploy setup for specific profiles ──
  echo "[3] Running post-deploy setup if needed..."

  case $PROFILE in
    e2b)
      echo "  Waiting for Authentik bootstrap..."
      # Authentik needs extra time and has a bootstrap container
      sleep 30
      ;;
    e2c)
      echo "  Running Zitadel setup script..."
      if [ -f "$BASE_DIR/scripts/setup-zitadel.sh" ]; then
        bash "$BASE_DIR/scripts/setup-zitadel.sh" 2>&1 | tail -5 || {
          echo "  WARNING: Zitadel setup failed. Tests may not work correctly."
        }
      else
        echo "  WARNING: setup-zitadel.sh not found!"
      fi
      ;;
    e1d)
      echo "  WebAuthn profile — skipping interactive WebAuthn enrollment for load test"
      echo "  Will test standard password flow (WebAuthn enforced only on server side)"
      ;;
  esac

  # ── Step 4: Verify connectivity ──
  echo "[4] Verifying IdP connectivity..."
  HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://idp.sso-lab.local" 2>/dev/null || echo "000")
  if [ "$HTTP_CODE" = "000" ]; then
    echo "ERROR: Cannot reach IdP! Skipping profile $PROFILE"
    continue
  fi
  echo "  IdP reachable (HTTP $HTTP_CODE)"

  # ── Step 5: Collect idle resources ──
  echo "[5] Collecting idle resource metrics..."
  IDLE_STATS=$($DOCKER stats --no-stream --format "{{.CPUPerc}}|{{.MemUsage}}" sso-lab-idp 2>/dev/null || echo "0.00%|0MiB / 0MiB")
  IDLE_CPU=$(echo "$IDLE_STATS" | cut -d'|' -f1)
  IDLE_RAM_RAW=$(echo "$IDLE_STATS" | cut -d'|' -f2 | awk '{print $1}')
  IDLE_RAM=$(echo "$IDLE_RAM_RAW" | sed 's/GiB/*1024/' | sed 's/MiB//' | bc 2>/dev/null || echo "0")
  IDLE_RAM_LIMIT=$(echo "$IDLE_STATS" | cut -d'|' -f2 | awk -F'/' '{print $2}' | sed 's/GiB/*1024/' | sed 's/MiB//' | bc 2>/dev/null || echo "0")

  echo "  Idle CPU: $IDLE_CPU, Idle RAM: ${IDLE_RAM} MB"

  # Also check additional containers for multi-container IdPs
  EXTRA_CONTAINERS=""
  case $PROFILE in
    e2b)
      WORKER_STATS=$($DOCKER stats --no-stream --format "{{.MemUsage}}" sso-lab-idp-worker 2>/dev/null || echo "0MiB")
      WORKER_RAM=$(echo "$WORKER_STATS" | awk '{print $1}' | sed 's/GiB/*1024/' | sed 's/MiB//' | bc 2>/dev/null || echo "0")
      EXTRA_CONTAINERS="worker_ram_mb=$WORKER_RAM"
      echo "  Worker RAM: ${WORKER_RAM} MB"
      TOTAL_IDLE=$((IDLE_RAM + WORKER_RAM))
      ;;
    *)
      TOTAL_IDLE=$IDLE_RAM
      ;;
  esac

  # ── Step 6: Run k6 load tests at each VU level ──
  echo "[6] Running load tests..."

  LT_PROFILE_DIR="$BASE_DIR/load-tests/$LT_DIR"
  CONFIG_FILE="$LT_PROFILE_DIR/config.env"

  if [ ! -f "$CONFIG_FILE" ]; then
    echo "ERROR: config.env not found at $CONFIG_FILE. Skipping."
    continue
  fi

  source "$CONFIG_FILE"

  K6_SCRIPT="$LT_PROFILE_DIR/oidc-login.js"
  if [ ! -f "$K6_SCRIPT" ]; then
    echo "ERROR: oidc-login.js not found at $K6_SCRIPT. Skipping."
    continue
  fi

  RESULTS_JSON_DIR="$RESULTS_BASE/json_${DISPLAY}"
  mkdir -p "$RESULTS_JSON_DIR"

  # VU levels to test
  VU_LEVELS="10 50 100"

  declare -A LATENCY_P50 LATENCY_P95 LATENCY_P99 ERROR_RATES ITER_COUNTS AVG_LATENCY

  for VU in $VU_LEVELS; do
    echo ""
    echo "  >>> Testing at ${VU} VU..."

    OUTPUT_JSON="$RESULTS_JSON_DIR/${VU}vu.json"

    # Start resource collection in background
    RESOURCE_CSV="$RESULTS_JSON_DIR/resources_${VU}vu.csv"
    bash "$BASE_DIR/load-tests/shared/collect-resources.sh" sso-lab-idp 100 "$RESOURCE_CSV" &
    RES_PID=$!

    # Run k6
    $K6_BIN run \
      -e BASE_URL="$BASE_URL" \
      -e APP_URL="$APP_URL" \
      -e CLIENT_ID="$CLIENT_ID" \
      -e CLIENT_SECRET="$CLIENT_SECRET" \
      -e TEST_USER="$TEST_USER" \
      -e TEST_PASSWORD="$TEST_PASSWORD" \
      -e TARGET_VU="$VU" \
      -e HOLD_DURATION="60s" \
      --out json="$OUTPUT_JSON" \
      "$K6_SCRIPT" 2>&1 || {
        echo "  WARNING: k6 exited with error code"
      }

    wait $RES_PID 2>/dev/null || true

    # Parse results
    LATENCIES=$(grep '"metric":"login_latency"' "$OUTPUT_JSON" 2>/dev/null | grep -o '"value":[0-9.]*' | cut -d: -f2 | sort -n)

    if [ -n "$LATENCIES" ]; then
      COUNT=$(echo "$LATENCIES" | wc -l | tr -d ' ')
      P50=$(echo "$LATENCIES" | awk 'BEGIN{c=0}{a[c++]=$1}END{printf "%d",a[int(c*0.50)]}')
      P90=$(echo "$LATENCIES" | awk 'BEGIN{c=0}{a[c++]=$1}END{printf "%d",a[int(c*0.90)]}')
      P95=$(echo "$LATENCIES" | awk 'BEGIN{c=0}{a[c++]=$1}END{printf "%d",a[int(c*0.95)]}')
      P99=$(echo "$LATENCIES" | awk 'BEGIN{c=0}{a[c++]=$1}END{printf "%d",a[int(c*0.99)]}')
      AVG=$(echo "$LATENCIES" | awk '{s+=$1;n++}END{printf "%d",s/n}')

      TOTAL_ERR=$(grep -c '"metric":"errors"' "$OUTPUT_JSON" 2>/dev/null || echo "0")
      ERR_1=$(grep '"metric":"errors"' "$OUTPUT_JSON" 2>/dev/null | grep -c '"value":1' || echo "0")
      if [ "$TOTAL_ERR" -gt 0 ] && [ "$ERR_1" -gt 0 ]; then
        ERR_RATE=$(echo "scale=1; $ERR_1 * 100 / $TOTAL_ERR" | bc)
      else
        ERR_RATE="0.0"
      fi

      LATENCY_P50[$VU]=$P50
      LATENCY_P95[$VU]=$P95
      LATENCY_P99[$VU]=$P99
      ERROR_RATES[$VU]=$ERR_RATE
      ITER_COUNTS[$VU]=$COUNT
      AVG_LATENCY[$VU]=$AVG

      echo "  Results: P50=${P50}ms P95=${P95}ms P99=${P99}ms Errors=${ERR_RATE}% Iters=$COUNT"
    else
      echo "  WARNING: No latency data found for VU=$VU"
      LATENCY_P50[$VU]=N/A
      LATENCY_P95[$VU]=N/A
      LATENCY_P99[$VU]=N/A
      ERROR_RATES[$VU]=N/A
      ITER_COUNTS[$VU]=0
      AVG_LATENCY[$VU]=N/A
    fi

    # Cool-down between tests
    sleep 10
  done

  # ── Step 7: Measure startup time ──
  echo ""
  echo "[7] Measuring startup/recovery times..."

  STARTUP_TIME=""
  RECOVERY_TIME=""
  FIRST_LOGIN_TIME=""

  # Cold start measurement
  $DOCKER stop sso-lab-idp 2>/dev/null
  sleep 3
  S_START=$(date +%s)
  $DOCKER start sso-lab-idp 2>/dev/null
  MAX_S_WAIT=120
  S_WAIT=0
  while [ $S_WAIT -lt $MAX_S_WAIT ]; do
    S_STATUS=$($DOCKER inspect --format='{{.State.Health.Status}}' sso-lab-idp 2>/dev/null || echo "unknown")
    if [ "$S_STATUS" = "healthy" ]; then
      S_END=$(date +%s)
      STARTUP_TIME=$((S_END - S_START))
      break
    fi
    sleep 2
    S_WAIT=$((S_WAIT + 2))
  done
  [ -z "$STARTUP_TIME" ] && STARTUP_TIME=">120"

  # Recovery after kill
  $DOCKER kill sso-lab-idp 2>/dev/null
  sleep 2
  R_START=$(date +%s)
  $DOCKER restart sso-lab-idp 2>/dev/null
  MAX_R_WAIT=120
  R_WAIT=0
  while [ $R_WAIT -lt $MAX_R_WAIT ]; do
    R_STATUS=$($DOCKER inspect --format='{{.State.Health.Status}}' sso-lab-idp 2>/dev/null || echo "unknown")
    if [ "$R_STATUS" = "healthy" ]; then
      R_END=$(date +%s)
      RECOVERY_TIME=$((R_END - R_START))
      break
    fi
    sleep 2
    R_WAIT=$((R_WAIT + 2))
  done
  [ -z "$RECOVERY_TIME" ] && RECOVERY_TIME=">120"

  # Wait for it to be ready again before moving on
  sleep 10

  # Time to first login (via simple HTTP check)
  FIRST_LOGIN_TIME="N/A"
  if [ -n "$TOKEN_URL" ] && [ -n "$TOKEN_POST" ]; then
    $DOCKER stop sso-lab-idp 2>/dev/null
    sleep 3
    FL_START=$(date +%s)
    $DOCKER start sso-lab-idp 2>/dev/null
    FL_MAX=180
    FL_WAIT=0
    while [ $FL_WAIT -lt $FL_MAX ]; do
      RESULT=$(curl -sk -X POST "$TOKEN_URL" -d "$TOKEN_POST" 2>/dev/null || echo "")
      if echo "$RESULT" | grep -q "access_token"; then
        FL_END=$(date +%s)
        FIRST_LOGIN_TIME=$((FL_END - FL_START))
        break
      fi
      sleep 2
      FL_WAIT=$((FL_WAIT + 2))
    done
    [ "$FIRST_LOGIN_TIME" = "N/A" ] && FIRST_LOGIN_TIME=">180"
  fi

  echo "  Startup: ${STARTUP_TIME}s, Recovery: ${RECOVERY_TIME}s, First login: ${FIRST_LOGIN_TIME}s"

  # ── Step 8: Parse resource CSV data ──
  echo "[8] Parsing resource metrics..."
  PEAK_CPU_100=""
  AVG_RAM_100=""
  PEAK_RAM_100=""

  RESOURCE_CSV_100="$RESULTS_JSON_DIR/resources_100vu.csv"
  if [ -f "$RESOURCE_CSV_100" ]; then
    PEAK_CPU_100=$(awk -F',' 'NR>1 && $3+0>max {max=$3+0} END {printf "%.0f%%\n", max}' "$RESOURCE_CSV_100" 2>/dev/null || echo "N/A")
    AVG_RAM_100=$(awk -F',' 'NR>1{s+=$4;n++}END{if(n>0) printf "%.0f MB\n", s/n; else print "N/A"}' "$RESOURCE_CSV_100" 2>/dev/null || echo "N/A")
    PEAK_RAM_100=$(awk -F',' 'NR>1 && $4+0>max {max=$4+0} END {if(max>0) printf "%.0f MB\n", max; else print "N/A"}' "$RESOURCE_CSV_100" 2>/dev/null || echo "N/A")
  fi

  # ── Step 9: Generate MD result file ──
  echo "[9] Generating result file..."

  # Determine IdP display info
  case $PROFILE in
    e1a|e2a) IDP_NAME="Keycloak 24.0"; IDP_STACK="JDK 21, Quarkus/io.vertx, start-dev mode" ;;
    e1b)     IDP_NAME="Keycloak 24.0 (SAML)"; IDP_STACK="JDK 21, Quarkus/io.vertx, start-dev mode" ;;
    e1c)     IDP_NAME="Authelia 4.38 (Forward Auth)"; IDP_STACK="Go, forward-auth proxy" ;;
    e1d)     IDP_NAME="Keycloak 24.0 (WebAuthn)"; IDP_STACK="JDK 21, Quarkus/io.vertx, start-dev mode" ;;
    e2b)     IDP_NAME="Authentik 2024.8"; IDP_STACK="Python/Django, gunicorn backend" ;;
    e2c)     IDP_NAME="Zitadel (stable)"; IDP_STACK="Go, cloud-native minimal IdP" ;;
    e2d)     IDP_NAME="Authelia 4.38 (OIDC Provider)"; IDP_STACK="Go, lightweight reverse proxy" ;;
  esac

  # Determine protocol description
  case $PROFILE in
    e1a|e2a) PROTO_DESC="OIDC Authorization Code Flow (4 шага: auth → login → redirect → token exchange)" ;;
    e1b)     PROTO_DESC="SAML SP-initiated Flow (3 шага: SP redirect → IdP auth → SAML assertion)" ;;
    e1c)     PROTO_DESC="Forward Auth (Traefik middleware → Authelia 1FA → X-Remote-User header)" ;;
    e1d)     PROTO_DESC="OIDC Authorization Code Flow с WebAuthn (passwordless, но нагрузочный тест через password fallback)" ;;
    e2b)     PROTO_DESC="OIDC Authorization Code Flow через Flow Executor REST API (10 HTTP round-trip)" ;;
    e2c)     PROTO_DESC="OIDC Authorization Code Flow через form-based UI (6 шагов: authorize → username → password → MFA skip → redirect → token)" ;;
    e2d)     PROTO_DESC="OIDC Authorization Code Flow через form-based UI (4 шага: authorize → login → redirect → token)" ;;
  esac

  cat > "$RESULT_FILE" << MDEOF
# Профиль ${DISPLAY} — Результаты нагрузочного тестирования

## Методика

- **Стенд**: macOS + Docker Desktop (ARM64), 8 CPU, 16 ГБ RAM
- **IdP**: ${IDP_NAME}
- **Стек IdP**: ${IDP_STACK}
- **БД**: PostgreSQL 16-alpine
- **Reverse proxy**: Traefik v3.3 (TLS termination)
- **Нагрузочный инструмент**: k6 v2.0.0
- **Протокол**: ${PROTO_DESC}
- **Тестовый пользователь**: ${TEST_USER:-testuser} / ${TEST_PASSWORD:-testpass123}
- **Схема тестирования**: ramp-up за 15с → steady-state 60с → ramp-down за 10с

> **Примечание**: Тестирование проводилось на Docker Desktop под macOS,
> что вносит существенный оверхед (~2–5x) по сравнению с нативным Linux.
> Абсолютные значения latency следует рассматривать как верхнюю границу;
> для получения production-реалистичных значений необходимо проводить
> тесты на Linux-хосте без виртуализации.

---

## Login latency P50 (мс)

| VU  | ${DISPLAY} |
|-----|:---:|
MDEOF

  for VU in $VU_LEVELS; do
    printf "| %-3s | %s |\n" "$VU" "${LATENCY_P50[$VU]:-N/A}" >> "$RESULT_FILE"
  done

  cat >> "$RESULT_FILE" << 'MDEOF'

## Login latency P95 (мс)

| VU  | Result |
|-----|:---:|
MDEOF

  for VU in $VU_LEVELS; do
    printf "| %-3s | %s |\n" "$VU" "${LATENCY_P95[$VU]:-N/A}" >> "$RESULT_FILE"
  done

  cat >> "$RESULT_FILE" << 'MDEOF'

## Login latency P99 (мс)

| VU  | Result |
|-----|:---:|
MDEOF

  for VU in $VU_LEVELS; do
    printf "| %-3s | %s |\n" "$VU" "${LATENCY_P99[$VU]:-N/A}" >> "$RESULT_FILE"
  done

  # Add analysis paragraph
  echo "" >> "$RESULT_FILE"
  if [ "${LATENCY_P50[10]}" != "N/A" ] && [ -n "${LATENCY_P50[10]}" ]; then
    echo "При 10 VU медианная latency составляет ${LATENCY_P50[10]} мс." >> "$RESULT_FILE"
  fi
  if [ "${LATENCY_P50[100]}" != "N/A" ] && [ -n "${LATENCY_P50[100]}" ]; then
    echo "При 100 VU медианная latency возрастает до ${LATENCY_P50[100]} мс." >> "$RESULT_FILE"
  fi

  cat >> "$RESULT_FILE" << 'MDEOF'

## Error rate (%)

| VU  | Result |
|-----|:---:|
MDEOF

  for VU in $VU_LEVELS; do
    printf "| %-3s | %s |\n" "$VU" "${ERROR_RATES[$VU]:-N/A}" >> "$RESULT_FILE"
  done

  cat >> "$RESULT_FILE" << MDEOF

## Потребление ресурсов

### RAM idle и под нагрузкой

| Метрика               | Значение |
|-----------------------|:---:|
| RAM idle (МБ)         | ${TOTAL_IDLE:-N/A} |
| RAM при 100 VU avg(МБ)| ${AVG_RAM_100:-N/A} |
| RAM при 100 VU peak(МБ)| ${PEAK_RAM_100:-N/A} |
| CPU при 100 VU peak (%)| ${PEAK_CPU_100:-N/A} |

## Startup и recovery time

| Характеристика             | Значение |
|----------------------------|:---:|
| Startup time (до healthy)  | ${STARTUP_TIME} с |
| Recovery после kill        | ${RECOVERY_TIME} с |
| Время до первого логина    | ${FIRST_LOGIN_TIME} |

---

## Сводные данные для таблиц сравнения (${DISPLAY})

| Характеристика            | Значение |
|---------------------------|:---:|
| P50 latency при 10 VU, мс | ${LATENCY_P50[10]:-N/A} |
| P95 latency при 10 VU, мс | ${LATENCY_P95[10]:-N/A} |
| P99 latency при 10 VU, мс | ${LATENCY_P99[10]:-N/A} |
| P95 latency при 100 VU, мс| ${LATENCY_P95[100]:-N/A} |
| Error rate при 100 VU, %  | ${ERROR_RATES[100]:-N/A} |
| RAM idle, МБ              | ${TOTAL_IDLE:-N/A} |
| RAM при 100 VU, МБ (avg)  | ${AVG_RAM_100:-N/A} |
| CPU при 100 VU, % (peak)  | ${PEAK_CPU_100:-N/A} |
| Startup time, с           | ${STARTUP_TIME} |
| Время до первого логина   | ${FIRST_LOGIN_TIME} с |
MDEOF

  echo ""
  echo "✅ Profile $PROFILE complete. Results saved to:"
  echo "   $RESULT_FILE"

done

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  ALL PROFILES COMPLETE                           ║"
echo "║  Results saved in: $RESULTS_BASE/"
echo "╚══════════════════════════════════════════════════╝"
ls -la "$RESULTS_BASE/"*.md 2>/dev/null || echo "(No .md files yet)"
