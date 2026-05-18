#!/usr/bin/env bash
# Shared helpers for attack scripts.
# macOS mDNS intercepts *.local lookups, breaking curl even with /etc/hosts.
# This helper adds --resolve flags to make curl use 127.0.0.1 for *.local hosts.

curl_resolve_args() {
  local url="$1"
  local host port
  host=$(echo "$url" | sed -E 's|https?://([^/:]+).*|\1|')
  port=$(echo "$url" | sed -nE 's|https?://[^/:]+:([0-9]+).*|\1|p')
  [[ -z "$port" ]] && { echo "$url" | grep -q "^https" && port=443 || port=80; }
  if [[ "$host" == *.local ]]; then
    echo "--resolve" "${host}:${port}:127.0.0.1"
  fi
}

# Wrapper around curl that auto-adds --resolve for .local hosts.
rcurl() {
  local resolve_args=()
  for arg in "$@"; do
    if [[ "$arg" == http://* ]] || [[ "$arg" == https://* ]]; then
      local host port
      host=$(echo "$arg" | sed -E 's|https?://([^/:]+).*|\1|')
      port=$(echo "$arg" | sed -nE 's|https?://[^/:]+:([0-9]+).*|\1|p')
      [[ -z "$port" ]] && { echo "$arg" | grep -q "^https" && port=443 || port=80; }
      if [[ "$host" == *.local ]]; then
        resolve_args+=(--resolve "${host}:${port}:127.0.0.1")
      fi
    fi
  done
  curl "${resolve_args[@]}" "$@"
}

# Base64url decode (no external deps, works on macOS & Linux)
b64url_decode() {
  local input="$1"
  # Add padding
  local pad=$(( (4 - ${#input} % 4) % 4 ))
  input="${input}$(printf '%0.s=' $(seq 1 $pad 2>/dev/null) || true)"
  # Translate base64url → base64 and decode
  printf '%s' "$input" | tr '_-' '/+' | base64 -d 2>/dev/null || true
}

# Base64url encode
b64url_encode() {
  printf '%s' "$1" | base64 | tr '+/' '-_' | tr -d '=' | tr -d '\n'
}

# Obtain an id_token via Keycloak ROPC grant.
# Usage: get_id_token <idp_url> [realm] [client_id] [client_secret] [username] [password]
# Prints the id_token to stdout.
get_id_token() {
  local idp_url="${1:?idp_url required}"
  local realm="${2:-sso-lab}"
  local client_id="${3:-sso-test-app}"
  local client_secret="${4:-testpass123}"
  local username="${5:-testuser}"
  local password="${6:-password123}"

  local token_url="${idp_url%/}/realms/${realm}/protocol/openid-connect/token"

  local response
  response=$(rcurl -sk -X POST "$token_url" \
    -d "grant_type=password" \
    -d "client_id=${client_id}" \
    -d "client_secret=${client_secret}" \
    -d "username=${username}" \
    -d "password=${password}" \
    -d "scope=openid" 2>/dev/null)

  # Extract id_token from JSON response
  echo "$response" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data.get('id_token', data.get('access_token', '')))
except:
    pass" 2>/dev/null
}

# Obtain a session cookie by performing browser-like OIDC login.
# Usage: get_session_cookie <app_url> <idp_url> [realm] [client_id] [client_secret] [username] [password]
# Prints cookie value to stdout.
get_session_cookie() {
  local app_url="${1:?app_url required}"
  local idp_url="${2:?idp_url required}"
  local realm="${3:-sso-lab}"
  local client_id="${4:-sso-test-app}"
  local client_secret="${5:-testpass123}"
  local username="${6:-testuser}"
  local password="${7:-password123}"

  # Use cookie jar to track session through OIDC flow
  local jar="/tmp/sso-attack-cookies-$$.txt"
  rm -f "$jar"

  # Step 1: Hit /login to start OIDC redirect chain
  rcurl -sk -L -c "$jar" -b "$jar" --max-redirs 10 \
    "${app_url%/}/login" -o /tmp/sso-attack-login-page.html 2>/dev/null || true

  # Step 2: If redirected to Keycloak login form, submit credentials
  local form_action
  form_action=$(grep -oP 'action="([^"]+)"' /tmp/sso-attack-login-page.html 2>/dev/null | head -1 | sed 's/action="//;s/"$//' || true)

  if [[ -n "$form_action" && "$form_action" == *"keycloak"* ]]; then
    # Replace HTML entities in action URL
    form_action=$(echo "$form_action" | sed 's/&amp;/\&/g')

    rcurl -sk -L -c "$jar" -b "$jar" --max-redirs 10 \
      -X POST "$form_action" \
      -d "username=${username}" \
      -d "password=${password}" \
      -d "credentialId=" \
      -o /dev/null 2>/dev/null || true
  fi

  # Extract session cookie
  local sess=""
  if [[ -f "$jar" ]]; then
    sess=$(grep -i "$(basename "$app_url" | sed 's/.*://')" "$jar" 2>/dev/null | awk '{print $NF}' | head -1 || true)
    [[ -z "$sess" ]] && sess=$(grep -P "\tsess\t" "$jar" 2>/dev/null | awk '{print $NF}' | head -1 || true)
    [[ -z "$sess" ]] && sess=$(grep -P "\tsession\t" "$jar" 2>/dev/null | awk '{print $NF}' | head -1 || true)
  fi

  echo "$sess"
  rm -f "$jar" /tmp/sso-attack-login-page.html
}
