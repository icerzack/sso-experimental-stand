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
#   bash A11_db_leak.sh [compose_dir_a_vuln] [compose_dir_c_vuln]
#
# Examples:
#   bash A11_db_leak.sh profile-a/vulnerable profile-c/vulnerable
#
# Result per finding:
#   CRITICAL — plaintext password / secret in DB
#   MEDIUM   — password hash (bcrypt/argon2/scrypt) found
#   LOW      — only public keys / non-sensitive crypto material
#   OK       — no sensitive data found / data encrypted at rest

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
    echo "  $label → SKIP (empty or not created)"
    RESULTS+=("$label:SKIP")
    return
  fi

  local plaintext hashes pubkeys
  # Plaintext passwords: lines containing "password" or common secret keywords not followed by a hash marker
  plaintext=$(strings "$file" 2>/dev/null | grep -iE 'password[^$]|secret[^$]|admin_token|api_key' | grep -viE '\$2[aby]\$|\$argon2|\$scrypt' | head -5 || true)
  # bcrypt / argon2 / scrypt hashes
  hashes=$(strings "$file" 2>/dev/null | grep -oE '\$2[aby]\$[0-9]+\$[A-Za-z0-9./]{53}|\$argon2[^\s]{10,}|\$scrypt\$[^\s]{10,}' | head -5 || true)
  # RSA / EC public key material
  pubkeys=$(strings "$file" 2>/dev/null | grep -c "BEGIN PUBLIC KEY\|BEGIN CERTIFICATE" || true)

  echo "  $label:"
  if [[ -n "$plaintext" ]]; then
    echo "    CRITICAL — plaintext sensitive values found:"
    while IFS= read -r line; do
      echo "      $(echo "$line" | cut -c1-100)"
    done <<< "$plaintext"
    RESULTS+=("$label:CRITICAL")
  elif [[ -n "$hashes" ]]; then
    echo "    MEDIUM — password hashes found (bcrypt/argon2/scrypt):"
    while IFS= read -r line; do
      echo "      ${line:0:60}…"
    done <<< "$hashes"
    RESULTS+=("$label:MEDIUM")
  elif [[ "$pubkeys" -gt 0 ]]; then
    echo "    LOW — only public keys / certificates found ($pubkeys items)"
    RESULTS+=("$label:LOW")
  else
    echo "    OK — no sensitive plaintext data found"
    RESULTS+=("$label:OK")
  fi
}

# ── Profile A: PostgreSQL dump ───────────────────────────────────────────────
echo "  [Profile A] PostgreSQL dump via docker exec"
PG_DUMP="$OUTDIR/profile_a_pg.sql"

# Detect running postgres container for profile-a/vulnerable
PG_CONTAINER=$(docker ps --format '{{.Names}}' 2>/dev/null | grep -E 'profile.a.vulnerable.*postgres|profile.a.vuln.*db' | head -1 || true)
if [[ -z "$PG_CONTAINER" ]]; then
  PG_CONTAINER=$(docker ps --format '{{.Names}}' 2>/dev/null | grep -i 'postgres' | head -1 || true)
fi

if [[ -n "$PG_CONTAINER" ]]; then
  echo "     Container: $PG_CONTAINER"
  docker exec "$PG_CONTAINER" \
    pg_dump -U keycloak -d keycloak --no-password --inserts -t user_entity -t credential \
    > "$PG_DUMP" 2>/dev/null || true
  echo "     Dump size: $(wc -c < "$PG_DUMP") bytes"
  classify_dump "ProfileA-PostgreSQL" "$PG_DUMP"
else
  echo "     No running PostgreSQL container found — skipping"
  RESULTS+=("ProfileA-PostgreSQL:SKIP")
fi
echo

# ── Profile B: in-memory only ────────────────────────────────────────────────
echo "  [Profile B] WebAuthn — no persistent DB (in-memory store)"
echo "     N/A — credentials exist only in process memory; no dump possible."
RESULTS+=("ProfileB-Store:N/A")
echo

# ── Profile C: Vaultwarden SQLite ────────────────────────────────────────────
echo "  [Profile C] Vaultwarden SQLite dump"
VW_DUMP="$OUTDIR/profile_c_vw.sqlite"

VW_CONTAINER=$(docker ps --format '{{.Names}}' 2>/dev/null | grep -E 'profile.c.*vaultwarden|vaultwarden' | head -1 || true)
if [[ -n "$VW_CONTAINER" ]]; then
  echo "     Container: $VW_CONTAINER"
  docker cp "$VW_CONTAINER:/data/db.sqlite3" "$VW_DUMP" 2>/dev/null || true
  if [[ -s "$VW_DUMP" ]]; then
    echo "     Dump size: $(wc -c < "$VW_DUMP") bytes"
    # Also try a text export if sqlite3 is available
    if command -v sqlite3 &>/dev/null; then
      sqlite3 "$VW_DUMP" ".dump users" > "${VW_DUMP}.txt" 2>/dev/null || true
      sqlite3 "$VW_DUMP" ".dump ciphers" >> "${VW_DUMP}.txt" 2>/dev/null || true
      classify_dump "ProfileC-SQLite-text" "${VW_DUMP}.txt"
    else
      classify_dump "ProfileC-SQLite-binary" "$VW_DUMP"
    fi
  else
    echo "     Could not copy SQLite file"
    RESULTS+=("ProfileC-SQLite:SKIP")
  fi
else
  echo "     No running Vaultwarden container found — skipping"
  RESULTS+=("ProfileC-SQLite:SKIP")
fi
echo

# ── Check for secrets in .env files ─────────────────────────────────────────
echo "  [Bonus] Checking .env files for hardcoded secrets"
find "$REPO_ROOT" -name ".env" -not -path "*/\.*" 2>/dev/null | while read -r envfile; do
  rel="${envfile#$REPO_ROOT/}"
  secrets=$(grep -E 'SECRET|PASSWORD|TOKEN|KEY' "$envfile" 2>/dev/null | grep -v '^#' | grep -v '=$' || true)
  if [[ -n "$secrets" ]]; then
    echo "     $rel → contains secret-like vars:"
    while IFS= read -r s; do
      echo "       $(echo "$s" | sed 's/=.*/=<redacted>/')"
    done <<< "$secrets"
  else
    echo "     $rel → no plaintext secrets detected"
  fi
done
echo

# ── Summary ──────────────────────────────────────────────────────────────────
echo "─── Summary ───────────────────────────────────"
for r in "${RESULTS[@]}"; do echo "  $r"; done
echo
WORST="OK"
for r in "${RESULTS[@]}"; do
  [[ "$r" == *CRITICAL* ]] && WORST="CRITICAL" && break
  [[ "$r" == *MEDIUM*   ]] && WORST="MEDIUM"
  [[ "$r" == *LOW*      ]] && [[ "$WORST" != "MEDIUM" ]] && WORST="LOW"
done
echo "Worst finding: $WORST"
