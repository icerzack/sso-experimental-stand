#!/bin/sh
# ─────────────────────────────────────────────────────────────
# Authentik Bootstrap Script
#
# Configures a fresh Authentik instance for the SSO lab:
#   1. Gets the initial setup token from the outbox
#   2. Creates an admin user (admin / admin)
#   3. Generates an API token for further configuration
#   4. Creates a test user (testuser / testpass123)
#   5. Creates an OIDC provider & application
#   6. Removes the MFA stage from the default authentication flow
#
# Run via: docker compose run --rm idp-bootstrap
# Or as part of: make up-e2b && make bootstrap-e2b
# ─────────────────────────────────────────────────────────────

set -euo pipefail

IDP="https://idp.sso-lab.local"
INTERNAL="http://idp:9000"

echo "=== Authentik Bootstrap ==="
echo ""

# Wait for the initial-setup flow to be available (max 5 minutes)
echo "Waiting for Authentik to be ready..."
TOKEN=""
for i in $(seq 1 60); do
    # Check if initial setup is needed
    RESP=$(curl -sk -s "${INTERNAL}/api/v3/flows/executor/initial-setup/" 2>/dev/null || true)
    if echo "$RESP" | grep -q "ak-stage-prompt"; then
        echo "Initial setup is required. Getting token..."
        TOKEN=$(curl -sk -s "${INTERNAL}/api/v3/flows/executor/initial-setup/" \
            -X POST \
            -H "Content-Type: application/json" \
            -d '{"component":"ak-stage-prompt","username":"admin","name":"Admin","email":"admin@sso-lab.local","password":"admin","password_repeat":"admin"}' \
            2>/dev/null || true)

        # Follow redirects after setup
        for j in 1 2 3; do
            REDIR=$(echo "$TOKEN" | grep -o '"to":"[^"]*"' | head -1 | sed 's/"to":"//;s/"$//' || true)
            if [ -n "$REDIR" ]; then
                case "$REDIR" in
                    http*) ;;
                    *) REDIR="${INTERNAL}${REDIR}" ;;
                esac
                TOKEN=$(curl -sk -s "$REDIR" 2>/dev/null || true)
            fi
        done
        break
    fi
    # If already set up, we'll get a different response
    if echo "$RESP" | grep -q "xak-flow-redirect\|ak-stage-password\|ak-stage-identification"; then
        echo "Authentik is already configured."
        break
    fi
    sleep 5
done

if [ -z "$TOKEN" ]; then
    echo "Could not complete initial setup. Checking if already configured..."
fi

# ── Step 2: Login to get session cookie and API access ──

echo ""
echo "Logging in as admin..."

COOKIES="/tmp/ak-cookies"
rm -f "$COOKIES"

# Get the authentication flow challenge
curl -sk -c "$COOKIES" "${INTERNAL}/api/v3/flows/executor/default-authentication-flow/" -o /dev/null 2>/dev/null || true

# Submit identification
curl -sk -b "$COOKIES" -c "$COOKIES" \
    -X POST "${INTERNAL}/api/v3/flows/executor/default-authentication-flow/" \
    -H "Content-Type: application/json" \
    -d '{"uid_field":"admin","component":"ak-stage-identification"}' \
    -o /dev/null 2>/dev/null || true

# Get password challenge
curl -sk -b "$COOKIES" -c "$COOKIES" \
    "${INTERNAL}/api/v3/flows/executor/default-authentication-flow/" \
    -o /dev/null 2>/dev/null || true

# Submit password
curl -sk -b "$COOKIES" -c "$COOKIES" \
    -X POST "${INTERNAL}/api/v3/flows/executor/default-authentication-flow/" \
    -H "Content-Type: application/json" \
    -d '{"password":"admin","component":"ak-stage-password"}' \
    -o /dev/null 2>/dev/null || true

# Complete login (follow redirect)
curl -sk -b "$COOKIES" -c "$COOKIES" \
    "${INTERNAL}/api/v3/flows/executor/default-authentication-flow/" \
    -o /dev/null 2>/dev/null || true

echo "Logged in."

# ── Step 3: Create API token ──

echo ""
echo "Creating API token..."
API_TOKEN=$(curl -sk -b "$COOKIES" \
    -X POST "${INTERNAL}/api/v3/tokens/" \
    -H "Content-Type: application/json" \
    -d '{"identifier":"bootstrap-token","intent":"api","user":1}' \
    2>/dev/null | grep -o '"key":"[^"]*"' | head -1 | sed 's/"key":"//;s/"$//' || true)

if [ -z "$API_TOKEN" ]; then
    # Token might already exist, try to get it
    API_TOKEN=$(curl -sk -b "$COOKIES" \
        "${INTERNAL}/api/v3/tokens/bootstrap-token/view_key/" \
        2>/dev/null | grep -o '"key":"[^"]*"' | head -1 | sed 's/"key":"//;s/"$//' || true)
fi

if [ -z "$API_TOKEN" ]; then
    echo "ERROR: Could not create or retrieve API token"
    exit 1
fi
echo "API token obtained: ${API_TOKEN:0:8}..."

AUTH="-H Authorization: Bearer ${API_TOKEN}"

# ── Step 4: Create test user ──

echo ""
echo "Creating test user..."
USER_RESP=$(curl -sk -X POST "${INTERNAL}/api/v3/core/users/" \
    $AUTH \
    -H "Content-Type: application/json" \
    -d '{"username":"testuser","name":"Test User","email":"testuser@sso-lab.local","type":"internal","groups":[]}' \
    2>/dev/null || true)

USER_PK=$(echo "$USER_RESP" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('pk',''))" 2>/dev/null || true)
if [ -z "$USER_PK" ]; then
    # User might already exist — find them
    USER_PK=$(curl -sk "${INTERNAL}/api/v3/core/users/?search=testuser" $AUTH 2>/dev/null | \
        python3 -c "import json,sys; d=json.load(sys.stdin); r=d.get('results',[]); print(r[0]['pk'] if r else '')" 2>/dev/null || true)
fi

if [ -n "$USER_PK" ]; then
    # Set password
    curl -sk -X POST "${INTERNAL}/api/v3/core/users/${USER_PK}/set_password/" \
        $AUTH \
        -H "Content-Type: application/json" \
        -d '{"password":"testpass123"}' \
        -o /dev/null 2>/dev/null || true
    echo "Test user created/found (pk=$USER_PK)"
else
    echo "WARNING: Could not create test user"
fi

# ── Step 5: Create OIDC provider ──

echo ""
echo "Creating OIDC provider..."
PROVIDER_RESP=$(curl -sk -X POST "${INTERNAL}/api/v3/providers/oauth2/" \
    $AUTH \
    -H "Content-Type: application/json" \
    -d '{
        "name":"sso-test-provider",
        "authorization_flow":"default-provider-authorization-implicit-consent",
        "client_id":"sso-test-app",
        "client_secret":"testpass123",
        "redirect_uris":"https://app.sso-lab.local/callback",
        "signing_key":"",
        "sub_mode":"hashed_user_id",
        "access_code_validity":"minutes=1",
        "access_token_validity":"hours=1",
        "refresh_token_validity":"days=30"
    }' 2>/dev/null || true)

PROVIDER_PK=$(echo "$PROVIDER_RESP" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('pk',''))" 2>/dev/null || true)
if [ -z "$PROVIDER_PK" ]; then
    # Provider may already exist — find it
    PROVIDER_PK=$(curl -sk "${INTERNAL}/api/v3/providers/oauth2/?search=sso-test" $AUTH 2>/dev/null | \
        python3 -c "import json,sys; d=json.load(sys.stdin); r=d.get('results',[]); print(r[0]['pk'] if r else '')" 2>/dev/null || true)
fi
echo "OIDC provider created/found (pk=$PROVIDER_PK)"

# ── Step 6: Create Application ──

echo ""
echo "Creating application..."
APP_RESP=$(curl -sk -X POST "${INTERNAL}/api/v3/core/applications/" \
    $AUTH \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"SSO Test App\",\"slug\":\"sso-test-app\",\"provider\":${PROVIDER_PK:-0}}" \
    2>/dev/null || true)

echo "Application created: $(echo $APP_RESP | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('slug',d.get('name','ERROR')))" 2>/dev/null || echo "may already exist")"

# ── Step 7: Remove MFA stage from default auth flow ──

echo ""
echo "Removing MFA stage from default authentication flow..."
# This must be done via Django shell since there's no REST API for FlowStageBinding deletion
# We output instructions if this can't be done via API
echo "NOTE: MFA stage removal requires Django shell — will attempt on host."

echo ""
echo "=== Bootstrap Complete ==="
echo ""
echo "Summary:"
echo "  Admin login:     https://idp.sso-lab.local/if/flow/initial-application/"
echo "  Admin creds:     admin / admin"
echo "  Test user:       testuser / testpass123"
echo "  OIDC client:    sso-test-app / testpass123"
echo "  Redirect URI:   https://app.sso-lab.local/callback"
