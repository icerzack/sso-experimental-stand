#!/bin/bash
# ============================================================================
# measure-startup.sh — Measure IdP container startup, recovery, and first login
# ============================================================================
# Usage:
#   ./shared/measure-startup.sh <container_name> [token_url] [token_post_data]
#
# Example:
#   ./shared/measure-startup.sh sso-lab-idp \
#     "https://idp.sso-lab.local/realms/sso-lab/protocol/openid-connect/token" \
#     "grant_type=password&client_id=sso-test-app&client_secret=testpass123&username=testuser&password=testpass123"
#
# Or use with config.env:
#   source profiles/A_keycloak/config.env
#   ./shared/measure-startup.sh $CONTAINER_NAME "$TOKEN_URL" "$TOKEN_POST_DATA"
# ============================================================================
set -euo pipefail

CONTAINER="${1:?Usage: measure-startup.sh <container_name> [token_url] [token_post_data]}"
TOKEN_URL="${2:-}"
TOKEN_POST="${3:-}"

DOCKER="/usr/local/bin/docker"

echo "╔════════════════════════════════════════════╗"
echo "║  Startup/Recovery Measurement: $CONTAINER"
echo "╚════════════════════════════════════════════╝"

# --- Measure Cold Startup ---
echo ""
echo "--- Cold Start (docker stop → start) ---"

$DOCKER stop "$CONTAINER" 2>/dev/null
sleep 3

START_TIME=$(date +%s)
$DOCKER start "$CONTAINER" 2>/dev/null

while true; do
  STATUS=$($DOCKER inspect --format='{{.State.Health.Status}}' "$CONTAINER" 2>/dev/null || echo "unknown")
  if [ "$STATUS" = "healthy" ]; then
    END_TIME=$(date +%s)
    COLD_START=$((END_TIME - START_TIME))
    echo "Cold startup time: ${COLD_START}s"
    break
  fi
  NOW=$(date +%s)
  if [ $((NOW - START_TIME)) -gt 180 ]; then
    echo "TIMEOUT: Container did not become healthy in 180s"
    COLD_START=">180"
    break
  fi
  sleep 1
done

# --- Measure Time to First Login ---
if [ -n "$TOKEN_URL" ] && [ -n "$TOKEN_POST" ]; then
  echo ""
  echo "--- Time to First Login ---"
  
  # Stop again for clean measurement
  $DOCKER stop "$CONTAINER" 2>/dev/null
  sleep 3
  
  START_TIME=$(date +%s)
  $DOCKER start "$CONTAINER" 2>/dev/null
  
  while true; do
    RESULT=$(curl -sk -X POST "$TOKEN_URL" -d "$TOKEN_POST" 2>/dev/null)
    
    if echo "$RESULT" | grep -q "access_token"; then
      END_TIME=$(date +%s)
      FIRST_LOGIN=$((END_TIME - START_TIME))
      FIRST_LOGIN_MIN=$(echo "scale=1; $FIRST_LOGIN / 60" | bc)
      echo "Time to first login: ${FIRST_LOGIN}s (~${FIRST_LOGIN_MIN} мин)"
      break
    fi
    
    NOW=$(date +%s)
    if [ $((NOW - START_TIME)) -gt 180 ]; then
      echo "TIMEOUT: First login not achieved in 180s"
      FIRST_LOGIN=">180"
      break
    fi
    sleep 1
  done
else
  echo ""
  echo "(Token URL not provided — skipping first-login measurement)"
  FIRST_LOGIN="N/A"
fi

# --- Measure Recovery After Kill ---
echo ""
echo "--- Recovery After Kill (docker kill → restart) ---"

$DOCKER kill "$CONTAINER" 2>/dev/null
sleep 2

START_TIME=$(date +%s)
$DOCKER restart "$CONTAINER" 2>/dev/null

while true; do
  STATUS=$($DOCKER inspect --format='{{.State.Health.Status}}' "$CONTAINER" 2>/dev/null || echo "unknown")
  if [ "$STATUS" = "healthy" ]; then
    END_TIME=$(date +%s)
    RECOVERY=$((END_TIME - START_TIME))
    echo "Recovery time: ${RECOVERY}s"
    break
  fi
  NOW=$(date +%s)
  if [ $((NOW - START_TIME)) -gt 180 ]; then
    echo "TIMEOUT: Container did not recover in 180s"
    RECOVERY=">180"
    break
  fi
  sleep 1
done

# --- Summary ---
echo ""
echo "╔════════════════════════════════════════════╗"
echo "║           STARTUP RESULTS SUMMARY          ║"
echo "╠════════════════════════════════════════════╣"
printf "║  Cold startup time:       %5s            ║\n" "$COLD_START"
printf "║  Recovery after kill:     %5s            ║\n" "$RECOVERY"
printf "║  Time to first login:     %5s            ║\n" "${FIRST_LOGIN}"
echo "╚════════════════════════════════════════════╝"

# Let the container stabilize after recovery
sleep 10

# Verify it's still healthy
STATUS=$($DOCKER inspect --format='{{.State.Health.Status}}' "$CONTAINER" 2>/dev/null || echo "unknown")
echo "Container status after stabilization: $STATUS"
