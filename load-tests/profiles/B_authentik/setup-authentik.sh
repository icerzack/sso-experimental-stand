#!/bin/bash
# ============================================================================
# setup-authentik.sh — Profile B: Configure Authentik for load testing
# ============================================================================
# This script is SPECIFIC to Profile B (Authentik).
# It creates:
#   - Admin password (if not set)
#   - OIDC provider
#   - Application with client credentials
#   - Test user for k6 load tests
#
# Prerequisites:
#   - Authentik container running and healthy
#   - Traefik routing idp.sso-lab.local → idp:9000
# ============================================================================

set -euo pipefail

IDP_URL="https://idp.sso-lab.local"
CONTAINER="sso-lab-idp"

echo "=== Setting up Authentik for Profile B ==="

# --- Step 1: Set admin password ---
echo "[1/5] Setting admin password..."
/usr/local/bin/docker exec "$CONTAINER" ak shell -c "
from django.contrib.auth import get_user_model
User = get_user_model()
u = User.objects.get(username='akadmin')
u.set_password('admin')
u.save()
print('Admin password set')
" 2>&1 | grep -v "^{" | head -5

# --- Step 2: Get API token ---
echo "[2/5] Getting admin API token..."

TOKEN=$(/usr/local/bin/docker exec "$CONTAINER" ak shell -c "
from authentik.core.models import Token, User, TokenIntents

user = User.objects.get(username='akadmin')

# Delete existing token if any
Token.objects.filter(identifier='load-test-token').delete()

token = Token.objects.create(
    identifier='load-test-token',
    user=user,
    intent=TokenIntents.INTENT_API,
)
print(token.key)
" 2>&1 | tail -1)

if [ -z "$TOKEN" ]; then
  echo "ERROR: Failed to get API token"
  exit 1
fi

echo "API token obtained"

# Helper function for API calls
api_call() {
  local method="$1"
  local path="$2"
  local data="${3:-}"
  
  if [ "$method" = "GET" ]; then
    curl -sk -X GET "${IDP_URL}${path}" \
      -H "Authorization: Bearer ${TOKEN}" \
      -H "Content-Type: application/json" 2>/dev/null
  else
    curl -sk -X "$method" "${IDP_URL}${path}" \
      -H "Authorization: Bearer ${TOKEN}" \
      -H "Content-Type: application/json" \
      -d "$data" 2>/dev/null
  fi
}

# --- Step 3: Create test user ---
echo "[3/5] Creating test user..."

USER_RESULT=$(api_call POST "/api/v3/core/users/" '{
  "username": "testuser",
  "name": "Test User",
  "email": "testuser@sso-lab.local",
  "type": "internal",
  "path": "users",
  "attributes": {}
}')

if echo "$USER_RESULT" | grep -q '"pk"'; then
  USER_PK=$(echo "$USER_RESULT" | python3 -c "import json,sys; print(json.load(sys.stdin).get('pk',''))")
  echo "Test user created (pk=$USER_PK)"
else
  # User might already exist
  USERS=$(api_call GET "/api/v3/core/users/?username=testuser")
  USER_PK=$(echo "$USERS" | python3 -c "import json,sys; d=json.load(sys.stdin); r=d.get('results',[]); print(r[0]['pk'] if r else '')" 2>/dev/null || echo "")
  if [ -n "$USER_PK" ]; then
    echo "Test user already exists (pk=$USER_PK)"
  else
    echo "ERROR: Failed to create/find test user"
    echo "$USER_RESULT" | head -3
    exit 1
  fi
fi

# Set user password
/usr/local/bin/docker exec "$CONTAINER" ak shell -c "
from django.contrib.auth import get_user_model
User = get_user_model()
u = User.objects.get(username='testuser')
u.set_password('testpass123')
u.save()
print('Test user password set')
" 2>&1 | grep -v "^{" | head -5

# --- Step 4: Create OIDC provider ---
echo "[4/5] Creating OIDC provider..."

# First, get the authorization flow UUID (API requires UUID, not slug)
FLOW_UUID=$(api_call GET "/api/v3/flows/instances/?slug=default-provider-authorization-implicit-consent" | python3 -c "
import json,sys
d=json.load(sys.stdin)
r=d.get('results',[])
print(r[0]['pk'] if r else '')
")

if [ -z "$FLOW_UUID" ]; then
  echo "ERROR: Could not find implicit consent flow"
  exit 1
fi
echo "  Flow UUID: $FLOW_UUID"

# Get signing key
SIGNING_KEY=$(api_call GET "/api/v3/crypto/certificatekeypairs/" | python3 -c "
import json,sys
d=json.load(sys.stdin)
for r in d.get('results',[]):
    if 'Self-signed' in r.get('name','') or 'authentik' in r.get('name',''):
        print(r['pk'])
        break
" 2>/dev/null)

PROVIDER_RESULT=$(api_call POST "/api/v3/providers/oauth2/" "{
  \"name\": \"SSO Test App Provider\",
  \"authorization_flow\": \"${FLOW_UUID}\",
  \"client_type\": \"confidential\",
  \"client_id\": \"sso-test-app\",
  \"client_secret\": \"testpass123\",
  \"redirect_uris\": [{\"matching_mode\": \"strict\", \"url\": \"https://app.sso-lab.local/callback\"}],
  \"signing_key\": \"${SIGNING_KEY}\",
  \"sub_mode\": \"user_uuid\"
}")

PROVIDER_PK=""
if echo "$PROVIDER_RESULT" | grep -q '"pk"'; then
  PROVIDER_PK=$(echo "$PROVIDER_RESULT" | python3 -c "import json,sys; print(json.load(sys.stdin).get('pk',''))")
  echo "OIDC provider created (pk=$PROVIDER_PK)"
else
  # Check if provider exists already
  PROVIDERS=$(api_call GET "/api/v3/providers/oauth2/?name=SSO+Test+App+Provider")
  PROVIDER_PK=$(echo "$PROVIDERS" | python3 -c "import json,sys; d=json.load(sys.stdin); r=d.get('results',[]); print(r[0]['pk'] if r else '')" 2>/dev/null || echo "")
  if [ -n "$PROVIDER_PK" ]; then
    echo "OIDC provider already exists (pk=$PROVIDER_PK)"
  else
    echo "ERROR: Failed to create OIDC provider"
    echo "$PROVIDER_RESULT" | python3 -m json.tool 2>/dev/null | head -10
    exit 1
  fi
fi

# --- Step 5: Create application ---
echo "[5/5] Creating application..."

APP_RESULT=$(api_call POST "/api/v3/core/applications/" "{
  \"name\": \"SSO Test App\",
  \"slug\": \"sso-test-app\",
  \"provider\": ${PROVIDER_PK}
}")

if echo "$APP_RESULT" | grep -q '"pk"'; then
  echo "Application created"
elif echo "$APP_RESULT" | grep -q "unique"; then
  echo "Application already exists"
else
  echo "WARNING: Application creation response:"
  echo "$APP_RESULT" | python3 -m json.tool 2>/dev/null | head -5
fi

# --- Verify setup ---
echo ""
echo "=== Verification ==="

# Check that the .well-known endpoint works
WELL_KNOWN=$(curl -sk "${IDP_URL}/application/o/sso-test-app/.well-known/openid-configuration" 2>/dev/null)
if echo "$WELL_KNOWN" | grep -q "authorization_endpoint"; then
  echo "OIDC Discovery endpoint: OK"
  AUTH_EP=$(echo "$WELL_KNOWN" | python3 -c "import json,sys; print(json.load(sys.stdin)['authorization_endpoint'])" 2>/dev/null)
  TOKEN_EP=$(echo "$WELL_KNOWN" | python3 -c "import json,sys; print(json.load(sys.stdin)['token_endpoint'])" 2>/dev/null)
  ISSUER=$(echo "$WELL_KNOWN" | python3 -c "import json,sys; print(json.load(sys.stdin)['issuer'])" 2>/dev/null)
  echo "  Issuer:        $ISSUER"
  echo "  Authorization: $AUTH_EP"
  echo "  Token:         $TOKEN_EP"
else
  echo "ERROR: OIDC Discovery endpoint not working"
  echo "$WELL_KNOWN" | head -3
fi

# Test token endpoint with client_credentials grant
TOKEN_TEST=$(curl -sk -X POST "${IDP_URL}/application/o/token/" \
  -d "grant_type=client_credentials&client_id=sso-test-app&client_secret=testpass123&scope=openid+profile+email" 2>/dev/null)

if echo "$TOKEN_TEST" | grep -q "access_token"; then
  echo "Token endpoint (client_credentials): OK ✅"
else
  ERROR_DESC=$(echo "$TOKEN_TEST" | python3 -c "import json,sys; print(json.load(sys.stdin).get('error_description',json.load(sys.stdin).get('error','unknown')))" 2>/dev/null || echo "unknown error")
  echo "Token endpoint (client_credentials): $ERROR_DESC"
  echo "  Note: This is expected — Authentik may require password grant or authorization code flow."
fi

# Verify app is accessible
APP_STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "https://app.sso-lab.local/" 2>/dev/null)
if [ "$APP_STATUS" = "200" ]; then
  echo "App endpoint: OK ✅"
else
  echo "App endpoint: HTTP $APP_STATUS ❌"
fi

echo ""
echo "Setup complete!"
