#!/usr/bin/env bash
#
# test-oidc-flow.sh — End-to-end OIDC Authorization Code Flow test
#
# Tests the complete flow against Authelia:
#   1. Discovery endpoint
#   2. JWKS endpoint  
#   3. Authentication (1FA login)
#   4. Consent acceptance (programmatic)
#   5. Authorization code exchange
#   6. Token validation (ID token decode)
#   7. UserInfo endpoint
#
# Usage:
#   ./scripts/test-oidc-flow.sh          # Test with alice/password1
#   ./scripts/test-oidc-flow.sh bob      # Test with bob/password2
#
set -euo pipefail

# ── Configuration ────────────────────────────────────────────────
IDP_HOST="idp.sso-lab.local"
APP_HOST="app.sso-lab.local"
CLIENT_ID="sso-test-app"
CLIENT_SECRET="testpass123"
USERNAME="${1:-alice}"
PASSWORD="${2:-password1}"
REDIRECT_URI="https://${APP_HOST}/callback"
SCOPES="openid profile email"
STATE="teststate_$(date +%s)"
NONCE="testnonce_$(date +%s)"

COLOR_GREEN="\033[0;32m"
COLOR_RED="\033[0;31m"
COLOR_YELLOW="\033[0;33m"
COLOR_CYAN="\033[0;36m"
COLOR_RESET="\033[0m"

pass() { echo -e "${COLOR_GREEN}✓ PASS${COLOR_RESET}: $1"; }
fail() { echo -e "${COLOR_RED}✗ FAIL${COLOR_RESET}: $1"; EXIT_CODE=1; }
info() { echo -e "${COLOR_CYAN}ℹ INFO${COLOR_RESET}: $1"; }
warn() { echo -e "${COLOR_YELLOW}⚠ WARN${COLOR_RESET}: $1"; }

EXIT_CODE=0
COOKIES=$(mktemp /tmp/oidc-cookies.XXXXXX)
trap 'rm -f "$COOKIES"' EXIT

AUTH_URL="https://${IDP_HOST}/api/oidc/authorization?client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&response_type=code&scope=${SCOPES// /+}&state=${STATE}&nonce=${NONCE}"

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  SSO Lab — OIDC End-to-End Flow Test"
echo "═══════════════════════════════════════════════════════════"
echo "  IDP:        https://${IDP_HOST}"
echo "  Client:     ${CLIENT_ID}"
echo "  User:       ${USERNAME}"
echo "  Redirect:   ${REDIRECT_URI}"
echo "  Scopes:     ${SCOPES}"
echo ""

# ── Step 1: OpenID Discovery ─────────────────────────────────
info "Step 1/7: Testing OpenID Discovery endpoint..."
DISCOVERY=$(/usr/bin/curl -sk "https://${IDP_HOST}/.well-known/openid-configuration" 2>/dev/null)

if echo "$DISCOVERY" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['issuer']=='https://${IDP_HOST}'" 2>/dev/null; then
    pass "Discovery endpoint returns valid issuer"
else
    fail "Discovery endpoint missing or invalid issuer"
    echo "  Response: ${DISCOVERY:0:200}"
fi

TOKEN_EP=$(echo "$DISCOVERY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token_endpoint',''))" 2>/dev/null)
if [[ "$TOKEN_EP" == *"/api/oidc/token"* ]]; then
    pass "Token endpoint found: ${TOKEN_EP}"
else
    fail "Token endpoint not found in discovery"
fi

# ── Step 2: JWKS ────────────────────────────────────────────
info "Step 2/7: Testing JWKS endpoint..."
JWKS=$(/usr/bin/curl -sk "https://${IDP_HOST}/jwks.json" 2>/dev/null)
KEY_COUNT=$(echo "$JWKS" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('keys',[])))" 2>/dev/null || echo "0")

if [[ "$KEY_COUNT" -gt 0 ]]; then
    pass "JWKS returns ${KEY_COUNT} key(s)"
else
    fail "JWKS endpoint returned no keys"
fi

# ── Step 3: Authentication (start OIDC flow + login) ─────────
info "Step 3/7: Starting OIDC authorization flow..."

# Hit authorization endpoint to establish session
/usr/bin/curl -sk -L -c "$COOKIES" "$AUTH_URL" 2>/dev/null > /dev/null

# Login with username/password
LOGIN_RESULT=$(/usr/bin/curl -sk -X POST -b "$COOKIES" -c "$COOKIES" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${USERNAME}\",\"password\":\"${PASSWORD}\"}" \
    "https://${IDP_HOST}/api/firstfactor" 2>/dev/null)

if echo "$LOGIN_RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['status']=='OK'" 2>/dev/null; then
    pass "Authentication successful for user '${USERNAME}'"
else
    fail "Authentication failed for user '${USERNAME}'"
    echo "  Response: ${LOGIN_RESULT:0:200}"
    exit 1
fi

# Verify session state
SESSION_STATE=$(/usr/bin/curl -sk -b "$COOKIES" "https://${IDP_HOST}/api/state" 2>/dev/null)
AUTH_LEVEL=$(echo "$SESSION_STATE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('authentication_level',0))" 2>/dev/null || echo "0")
if [[ "$AUTH_LEVEL" -ge 1 ]]; then
    pass "Session authenticated at level ${AUTH_LEVEL}"
else
    fail "Session not properly authenticated"
fi

# ── Step 4: Consent acceptance ──────────────────────────────
info "Step 4/7: Accepting consent..."

# Request authorization to get consent redirect
AUTH_HEADERS=$(/usr/bin/curl -sk -D - -o /dev/null \
    -b "$COOKIES" -c "$COOKIES" "$AUTH_URL" 2>/dev/null)

CONSENT_ID=$(echo "$AUTH_HEADERS" | /usr/bin/grep -i "^location:" | /usr/bin/grep -o 'id=[^[:space:]&]*' | cut -d= -f2 | tr -d '\r')

if [[ -z "$CONSENT_ID" ]]; then
    # No consent needed — might have been pre-configured or auto-accepted
    warn "No consent page detected (may be auto-accepted)"
    
    # Check if we already got redirected to callback with a code
    CALLBACK_URL=$(echo "$AUTH_HEADERS" | /usr/bin/grep -i "^location:" | tr -d '\r' | awk '{print $2}')
    if [[ "$CALLBACK_URL" == *"code="* ]]; then
        AUTH_CODE=$(echo "$CALLBACK_URL" | /usr/bin/grep -o 'code=[^&]*' | cut -d= -f2)
        pass "Authorization code received directly (no consent required)"
    fi
fi

if [[ -n "$CONSENT_ID" ]]; then
    info "Consent ID: ${CONSENT_ID}"

    # Visit consent page (needed for proper session flow)
    /usr/bin/curl -sk -L -b "$COOKIES" -c "$COOKIES" \
        "https://${IDP_HOST}/consent?id=${CONSENT_ID}" 2>/dev/null > /dev/null

    # Accept consent via API (same format Authelia's SPA uses)
    CONSENT_RESULT=$(/usr/bin/curl -sk -X POST -b "$COOKIES" -c "$COOKIES" \
        -H "Content-Type: application/json" \
        -d "{\"id\":\"${CONSENT_ID}\",\"client_id\":\"${CLIENT_ID}\",\"consent\":true,\"pre_configure\":true}" \
        "https://${IDP_HOST}/api/oidc/consent" 2>/dev/null)

    REDIRECT_FROM_CONSENT=$(echo "$CONSENT_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('redirect_uri',''))" 2>/dev/null)

    if [[ -n "$REDIRECT_FROM_CONSENT" ]]; then
        pass "Consent accepted, got redirect URL"

        # Follow the redirect to get the authorization code
        CODE_HEADERS=$(/usr/bin/curl -sk -D - -o /dev/null \
            -b "$COOKIES" -c "$COOKIES" "$REDIRECT_FROM_CONSENT" 2>/dev/null)
        
        CALLBACK_LOCATION=$(echo "$CODE_HEADERS" | /usr/bin/grep -i "^location:" | tr -d '\r' | awk '{print $2}')
        
        if [[ "$CALLBACK_LOCATION" == *"code="* ]]; then
            AUTH_CODE=$(echo "$CALLBACK_LOCATION" | python3 -c "
import sys, urllib.parse
url = sys.stdin.read().strip()
parsed = urllib.parse.urlparse(url)
params = urllib.parse.parse_qs(parsed.query)
print(params.get('code', [''])[0])
" 2>/dev/null)
            pass "Got authorization code from callback"
        else
            fail "No authorization code in callback"
            echo "  Location: ${CALLBACK_LOCATION:0:200}"
        fi
    else
        fail "Consent acceptance failed"
        echo "  Response: ${CONSENT_RESULT:0:300}"
    fi
fi

if [[ -z "${AUTH_CODE:-}" ]]; then
    fail "No authorization code obtained — cannot continue"
    exit 1
fi

info "Auth code: ${AUTH_CODE:0:30}..."

# ── Step 5: Token exchange ──────────────────────────────────
info "Step 5/7: Exchanging authorization code for tokens..."

TOKEN_RESPONSE=$(/usr/bin/curl -sk -X POST \
    -u "${CLIENT_ID}:${CLIENT_SECRET}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=authorization_code&code=${AUTH_CODE}&redirect_uri=${REDIRECT_URI}" \
    "https://${IDP_HOST}/api/oidc/token" 2>/dev/null)

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
ID_TOKEN=$(echo "$TOKEN_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id_token',''))" 2>/dev/null)
TOKEN_TYPE=$(echo "$TOKEN_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token_type',''))" 2>/dev/null)
EXPIRES_IN=$(echo "$TOKEN_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('expires_in',''))" 2>/dev/null)

if [[ -n "$ACCESS_TOKEN" ]]; then
    pass "Access token received (${TOKEN_TYPE}, expires in ${EXPIRES_IN}s)"
else
    fail "Failed to obtain access token"
    ERROR=$(echo "$TOKEN_RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error','') + ': ' + d.get('error_description',''))" 2>/dev/null)
    echo "  Error: ${ERROR}"
fi

if [[ -n "$ID_TOKEN" ]]; then
    pass "ID token received"
else
    fail "No ID token in response"
fi

# ── Step 6: ID Token validation ─────────────────────────────
info "Step 6/7: Validating ID token claims..."

if [[ -n "$ID_TOKEN" ]]; then
    ID_PAYLOAD=$(echo "$ID_TOKEN" | cut -d. -f2 | python3 -c "
import base64, json, sys
payload = sys.stdin.read().strip()
padding = 4 - len(payload) % 4
if padding != 4:
    payload += '=' * padding
decoded = base64.urlsafe_b64decode(payload)
data = json.loads(decoded)
for k, v in sorted(data.items()):
    print(f'{k}={v}')
" 2>/dev/null)

    TOKEN_ISS=$(echo "$ID_PAYLOAD" | /usr/bin/grep '^iss=' | cut -d= -f2)
    TOKEN_SUB=$(echo "$ID_PAYLOAD" | /usr/bin/grep '^sub=' | cut -d= -f2)
    TOKEN_AUD=$(echo "$ID_PAYLOAD" | /usr/bin/grep '^aud=' | cut -d= -f2)
    TOKEN_EMAIL=$(echo "$ID_PAYLOAD" | /usr/bin/grep '^email=' | cut -d= -f2)
    TOKEN_NAME=$(echo "$ID_PAYLOAD" | /usr/bin/grep '^name=' | cut -d= -f2)
    TOKEN_NONCE=$(echo "$ID_PAYLOAD" | /usr/bin/grep '^nonce=' | cut -d= -f2)
    TOKEN_PREFERRED_USERNAME=$(echo "$ID_PAYLOAD" | /usr/bin/grep '^preferred_username=' | cut -d= -f2)

    if [[ "$TOKEN_ISS" == "https://${IDP_HOST}" ]]; then
        pass "Issuer correct: ${TOKEN_ISS}"
    else
        fail "Issuer mismatch: expected https://${IDP_HOST}, got ${TOKEN_ISS}"
    fi

    if [[ -n "$TOKEN_SUB" ]]; then
        pass "Subject (sub) present: ${TOKEN_SUB}"
    else
        fail "Missing subject claim"
    fi

    if [[ "$TOKEN_AUD" == *"${CLIENT_ID}"* ]] || [[ "$TOKEN_AUD" == "[${CLIENT_ID}]" ]]; then
        pass "Audience matches client_id"
    else
        fail "Audience mismatch: expected ${CLIENT_ID}, got ${TOKEN_AUD}"
    fi

    if [[ "$TOKEN_NONCE" == "$NONCE" ]]; then
        pass "Nonce matches: ${NONCE}"
    else
        fail "Nonce mismatch: expected ${NONCE}, got ${TOKEN_NONCE}"
    fi

    if [[ -n "$TOKEN_EMAIL" ]]; then
        pass "Email claim present: ${TOKEN_EMAIL}"
    else
        warn "No email claim in ID token"
    fi

    if [[ -n "$TOKEN_NAME" ]]; then
        pass "Name claim present: ${TOKEN_NAME}"
    else
        warn "No name claim in ID token"
    fi

    info "ID token claims:"
    echo "$ID_PAYLOAD" | while IFS='=' read -r key value; do
        printf "    %-25s %s\n" "$key" "$value"
    done
fi

# ── Step 7: UserInfo endpoint ───────────────────────────────
info "Step 7/7: Testing UserInfo endpoint..."

if [[ -n "$ACCESS_TOKEN" ]]; then
    USERINFO=$(/usr/bin/curl -sk -H "Authorization: Bearer ${ACCESS_TOKEN}" \
        "https://${IDP_HOST}/api/oidc/userinfo" 2>/dev/null)

    UI_SUB=$(echo "$USERINFO" | python3 -c "import sys,json; print(json.load(sys.stdin).get('sub',''))" 2>/dev/null)
    UI_EMAIL=$(echo "$USERINFO" | python3 -c "import sys,json; print(json.load(sys.stdin).get('email',''))" 2>/dev/null)
    UI_NAME=$(echo "$USERINFO" | python3 -c "import sys,json; print(json.load(sys.stdin).get('name',''))" 2>/dev/null)
    UI_USERNAME=$(echo "$USERINFO" | python3 -c "import sys,json; print(json.load(sys.stdin).get('preferred_username',''))" 2>/dev/null)

    if [[ -n "$UI_SUB" ]]; then
        pass "UserInfo returned subject: ${UI_SUB}"
    else
        fail "UserInfo missing subject"
    fi

    if [[ -n "$UI_EMAIL" ]]; then
        pass "UserInfo email: ${UI_EMAIL}"
    else
        warn "UserInfo missing email"
    fi

    if [[ -n "$UI_NAME" ]]; then
        pass "UserInfo name: ${UI_NAME}"
    else
        warn "UserInfo missing name"
    fi

    if [[ -n "$UI_USERNAME" ]]; then
        pass "UserInfo preferred_username: ${UI_USERNAME}"
    else
        warn "UserInfo missing preferred_username"
    fi

    if [[ "$UI_SUB" == "$TOKEN_SUB" ]]; then
        pass "UserInfo sub matches ID token sub"
    else
        fail "UserInfo sub does NOT match ID token sub"
    fi
fi

# ── Summary ─────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════"
if [[ $EXIT_CODE -eq 0 ]]; then
    echo -e "  ${COLOR_GREEN}All OIDC tests passed! ✓${COLOR_RESET}"
else
    echo -e "  ${COLOR_RED}Some tests failed ✗${COLOR_RESET}"
fi
echo "═══════════════════════════════════════════════════════════"
echo ""

exit $EXIT_CODE
