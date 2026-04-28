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
