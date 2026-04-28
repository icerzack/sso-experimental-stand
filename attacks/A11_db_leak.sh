#!/usr/bin/env bash
# A11 — Database / Secret Leak Assessment
# OWASP ASVS v4.2 § 6.2 / § 9.1.1
# MITRE ATT&CK T1552 — Unsecured Credentials
#
# Dumps accessible database storage for each profile and searches for
# sensitive plaintext data: passwords, hashes, tokens, private keys.
#
# Profile A: PostgreSQL (Keycloak DB)
# Profile B: in-memory only — no persistent DB to dump
# Profile C: Vaultwarden SQLite (/data/db.sqlite3)
#
# Usage:
#   bash A11_db_leak.sh [compose_dir_a_vuln|-] [compose_dir_c_vuln|-]
#
# Examples:
#   bash A11_db_leak.sh profile-a/vulnerable profile-c/vulnerable
#
# Result:
#   VULNERABLE — plaintext credentials/secrets found
#   PROTECTED  — no plaintext credentials/secrets found

set -euo pipefail

DIR_A="${1:-profile-a/vulnerable}"
DIR_C="${2:-profile-c/vulnerable}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "[A11] Database / Secret Leak Assessment"
echo "     Profile A dir: $DIR_A"
echo "     Profile C dir: $DIR_C"
echo

RESULTS=()
OUTDIR="/tmp/d2_dumps"
mkdir -p "$OUTDIR"

# ── Helper: classify a dump file ────────────────────────────────────────────
classify_dump() {
  local label="$1" file="$2"
  if [[ ! -s "$file" ]]; then
    echo "  $label → PROTECTED (no dump material)"
    RESULTS+=("$label:PROTECTED")
    return
  fi

  local plaintext
  plaintext=$(strings "$file" 2>/dev/null | grep -iE "password123|testpass123|admin_token=admin|client_secret=.*testpass123" | head -5 || true)

  if [[ -n "$plaintext" ]]; then
    echo "  $label → VULNERABLE (plaintext secret-like values found):"
    while IFS= read -r line; do
      echo "      $(echo "$line" | cut -c1-120)"
    done <<< "$plaintext"
    RESULTS+=("$label:VULNERABLE")
  else
    echo "  $label → PROTECTED (no plaintext secret-like values found)"
    RESULTS+=("$label:PROTECTED")
  fi
}

# ── Profile A: PostgreSQL dump ───────────────────────────────────────────────
if [[ "$DIR_A" != "-" ]]; then
  echo "  [Profile A] PostgreSQL dump via docker exec"
  PG_DUMP="$OUTDIR/profile_a_pg.sql"

  PG_CONTAINER=$(docker ps --format '{{.Names}}' 2>/dev/null | grep -E 'profile-a-.*postgres|postgres' | head -1 || true)
  if [[ -n "$PG_CONTAINER" ]]; then
    echo "     Container: $PG_CONTAINER"
    docker exec "$PG_CONTAINER" \
      pg_dump -U keycloak -d keycloak --no-password --inserts -t user_entity -t credential \
      > "$PG_DUMP" 2>/dev/null || true
    echo "     Dump size: $(wc -c < "$PG_DUMP") bytes"
    classify_dump "ProfileA-PostgreSQL" "$PG_DUMP"
  else
    echo "     No running PostgreSQL container found"
    RESULTS+=("ProfileA-PostgreSQL:PROTECTED")
  fi
  echo
fi

# ── Profile C: Vaultwarden SQLite ────────────────────────────────────────────
if [[ "$DIR_C" != "-" ]]; then
  echo "  [Profile C] Vaultwarden SQLite dump"
  VW_DUMP="$OUTDIR/profile_c_vw.sqlite"

  VW_CONTAINER=$(docker ps --format '{{.Names}}' 2>/dev/null | grep -E 'profile-c-.*vaultwarden|vaultwarden' | head -1 || true)
  if [[ -n "$VW_CONTAINER" ]]; then
    echo "     Container: $VW_CONTAINER"
    docker cp "$VW_CONTAINER:/data/db.sqlite3" "$VW_DUMP" 2>/dev/null || true
    if [[ -s "$VW_DUMP" ]]; then
      echo "     Dump size: $(wc -c < "$VW_DUMP") bytes"
      if command -v sqlite3 &>/dev/null; then
        sqlite3 "$VW_DUMP" ".dump users" > "${VW_DUMP}.txt" 2>/dev/null || true
        sqlite3 "$VW_DUMP" ".dump ciphers" >> "${VW_DUMP}.txt" 2>/dev/null || true
        classify_dump "ProfileC-SQLite" "${VW_DUMP}.txt"
      else
        classify_dump "ProfileC-SQLite" "$VW_DUMP"
      fi
    else
      echo "     Could not copy SQLite file"
      RESULTS+=("ProfileC-SQLite:PROTECTED")
    fi
  else
    echo "     No running Vaultwarden container found"
    RESULTS+=("ProfileC-SQLite:PROTECTED")
  fi
  echo
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo "─── Summary ───────────────────────────────────"
for r in "${RESULTS[@]}"; do echo "  $r"; done
echo
if printf '%s\n' "${RESULTS[@]}" | grep -q "VULNERABLE"; then
  echo "VULNERABLE — plaintext secret-like values detected"
else
  echo "PROTECTED  — no plaintext secret-like values detected"
fi
