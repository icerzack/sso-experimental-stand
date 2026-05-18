#!/usr/bin/env bash
# ┌──────────────────────────────────────────────────────────┐
# │ setup-zitadel.sh                                        │
# │ Post-deploy configuration for Zitadel IdP               │
# │ Creates OIDC client app, test users, and grants         │
# └──────────────────────────────────────────────────────────┘
set -euo pipefail

BASE_URL="https://idp.sso-lab.local"
CONSOLE_CLIENT_ID="373396807394263049@zitadel"
ADMIN_USERNAME="zitadel-admin@zitadel.idp.sso-lab.local"
ADMIN_PASSWORD="${ZITADEL_ADMIN_PASSWORD:-Admin123!}"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log()  { echo -e "${GREEN}[SETUP]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()  { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# -----------------------------------------------------------
# Step 1: Wait for Zitadel to be healthy
# -----------------------------------------------------------
log "Waiting for Zitadel to become ready..."
for i in $(seq 1 30); do
    if curl -sk -o /dev/null -w '%{http_code}' "$BASE_URL/debug/healthz" 2>/dev/null | grep -q '200'; then
        log "Zitadel is healthy!"
        break
    fi
    if [ "$i" -eq 30 ]; then
        err "Zitadel did not become healthy in time!"
        exit 1
    fi
    sleep 5
done

# -----------------------------------------------------------
# Step 2: Obtain admin access token via OIDC browser flow
#   (automated with Python)
# -----------------------------------------------------------
log "Obtaining admin access token..."

ACCESS_TOKEN=$(python3 << 'PYEOF'
import urllib.request, urllib.parse, http.cookiejar, json, re, ssl, hashlib, base64, secrets, sys

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

base_url = "https://idp.sso-lab.local"
CID = "373395691088642057@zitadel"

code_verifier = secrets.token_urlsafe(32)
code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).rstrip(b'=').decode()

def gcsrf(h):
    m = re.search(r'name="gorilla\.csrf\.Token"[^>]*value="([^"]+)"', h)
    return m.group(1) if m else None

class NR(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*a,**kw): return None

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=ssl_ctx),
    urllib.request.HTTPCookieProcessor(cj), NR())

def R(url, data=None, hdrs=None):
    if not hdrs: hdrs = {}
    if isinstance(data, dict): data = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=data, headers=hdrs)
    try:
        resp = opener.open(req)
        return resp.status, resp.read().decode(), resp.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode() if e.fp else "", e.headers

def FI(html):
    ar = re.search(r'name="authRequestID"[^>]*value="([^"]*)"', html)
    fa = re.search(r'<form[^>]*action="([^"]*)"', html)
    return gcsrf(html), ar.group(1) if ar else "", fa.group(1) if fa else ""

def follow(s,b,h,mx=10):
    for _ in range(mx):
        if s in (302,303,301):
            loc=h.get('Location','')
            if not loc.startswith("http"): loc=base_url+loc
            cm=re.search(r'[?&]code=([^&]+)',loc)
            if cm: return ("code",cm.group(1))
            s,b,h=R(loc)
        elif s==200:
            csrf,aid,act=FI(b)
            return ("page",b,h,csrf,aid,act)
        else: return ("err",f"HTTP {s}")
    return ("loop",)

scope="openid profile email urn:zitadel:iam:org:project:id:zitadel:aud"
redirect_uri=f"{base_url}/ui/console/auth/callback"
url=(f"{base_url}/oauth/v2/authorize?client_id={CID}"
     f"&redirect_uri={urllib.parse.quote(redirect_uri)}"
     f"&response_type=code&scope={urllib.parse.quote(scope)}"
     f"&code_challenge={code_challenge}&code_challenge_method=S256")

s,b,h=R(url); result=follow(s,b,h)
if result[0]!="page": sys.exit(1)
_,body,_,csrf,aid,act=result

s,b,h=R(base_url+act,{"gorilla.csrf.Token":csrf,"loginname":"zitadel-admin@zitadel.idp.sso-lab.local","authRequestID":aid},{"Content-Type":"application/x-www-form-urlencoded"})
result=follow(s,b,h)
if result[0]!="page": sys.exit(1)
_,body,_,csrf,aid,act=result

s,b,h=R(base_url+act,{"gorilla.csrf.Token":csrf,"password":"Admin123!","authRequestID":aid},{"Content-Type":"application/x-www-form-urlencoded"})
result=follow(s,b,h)

while result[0]=="page":
    _,body,_,csrf,aid,act=result
    if "mfa/prompt" in act:
        s,b,h=R(base_url+act,{"gorilla.csrf.Token":csrf,"skip":"true","authRequestID":aid},{"Content-Type":"application/x-www-form-urlencoded"})
        result=follow(s,b,h); continue
    break

if result[0]!="code":
    print(f"Failed to get auth code", file=sys.stderr)
    sys.exit(1)

code=result[1]
td=urllib.parse.urlencode({
    "grant_type":"authorization_code","code":code,
    "redirect_uri":redirect_uri,"client_id":CID,
    "code_verifier":code_verifier}).encode()
st,tb,_=R(f"{base_url}/oauth/v2/token",td,{"Content-Type":"application/x-www-form-urlencoded"})
if st!=200:
    print(f"Token exchange failed: {st} {tb[:100]}", file=sys.stderr)
    sys.exit(1)
print(json.loads(tb).get('access_token',''))
PYEOF
)

if [ -z "$ACCESS_TOKEN" ]; then
    err "Failed to obtain access token!"
    exit 1
fi
log "Access token obtained!"

# Helper function for API calls
api_call() {
    local method="${1:-GET}"
    local path="$2"
    local data="${3:-}"
    
    if [ -n "$data" ]; then
        curl -sk -X "$method" \
            -H "Authorization: Bearer $ACCESS_TOKEN" \
            -H "Content-Type: application/json" \
            -d "$data" \
            "$BASE_URL$path"
    else
        curl -sk -X "$method" \
            -H "Authorization: Bearer $ACCESS_TOKEN" \
            "$BASE_URL$path"
    fi
}

# -----------------------------------------------------------
# Step 3: Create project (if not exists)
# -----------------------------------------------------------
log "Creating SSO Lab Apps project..."
PROJECT_RESULT=$(api_call POST "/management/v1/projects" '{"name":"SSO Lab Apps"}')
PROJECT_ID=$(echo "$PROJECT_RESULT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('id',''))" 2>/dev/null || true)

if [ -z "$PROJECT_ID" ]; then
    # Project might already exist — search for it
    warn "Project creation returned no ID, searching..."
    PROJECT_ID=$(api_call POST "/management/v1/projects/_search" '{}' | \
        python3 -c "import json,sys; [print(p['id']) for p in json.load(sys.stdin).get('result',[]) if p.get('name','').lower()=='sso lab apps']" 2>/dev/null | head -1 || true)
fi

if [ -z "$PROJECT_ID" ]; then
    err "Could not create or find project!"
    exit 1
fi
log "Project ID: $PROJECT_ID"

# -----------------------------------------------------------
# Step 4: Create OIDC client application
# -----------------------------------------------------------
log "Creating OIDC client application..."
APP_RESULT=$(api_call POST "/management/v1/projects/$PROJECT_ID/apps/oidc" '{
    "name": "sso-test-app",
    "redirectUris": [
        "https://app.sso-lab.local/auth/callback",
        "https://app.sso-lab.local/login/callback",
        "https://app.sso-lab.local/callback"
    ],
    "postLogoutRedirectUris": ["https://app.sso-lab.local/"],
    "responseTypes": ["OIDC_RESPONSE_TYPE_CODE"],
    "grantTypes": [
        "OIDC_GRANT_TYPE_AUTHORIZATION_CODE",
        "OIDC_GRANT_TYPE_REFRESH_TOKEN"
    ],
    "appType": "OIDC_APP_TYPE_WEB",
    "authMethodType": "OIDC_AUTH_METHOD_TYPE_POST",
    "accessTokenType": "OIDC_ACCESS_TOKEN_TYPE_JWT",
    "devMode": true
}')

CLIENT_ID=$(echo "$APP_RESULT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('clientId',''))" 2>/dev/null || true)
CLIENT_SECRET=$(echo "$APP_RESULT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('clientSecret',''))" 2>/dev/null || true)

if [ -z "$CLIENT_ID" ]; then
    err "Failed to create OIDC client app!"
    echo "$APP_RESULT"
    exit 1
fi
log "Client ID: $CLIENT_ID"
log "Client Secret: ${CLIENT_SECRET:0:10}..."

# -----------------------------------------------------------
# Step 5: Configure SMTP (required for sending init/verification emails)
# -----------------------------------------------------------
log "Configuring SMTP via admin API..."
SMTP_RESULT=$(api_call POST "/admin/v1/smtp" '{
    "host": "mailhog:1025",
    "senderAddress": "noreply@sso-lab.local",
    "senderName": "SSO Lab",
    "tls": false,
    "description": "MailHog SMTP for testing"
}')
if echo "$SMTP_RESULT" | python3 -c "import json,sys; d=json.load(sys.stdin); sys.exit(0 if d.get('id') else 1)" 2>/dev/null; then
    log "SMTP configured!"
else
    warn "SMTP configuration may have failed: $SMTP_RESULT"
fi

# -----------------------------------------------------------
# Step 6: Create test users
# -----------------------------------------------------------
log "Creating test user: alice@idp.sso-lab.local ..."
ALICE_RESULT=$(api_call POST "/management/v1/users/human/_import" '{
    "userName": "alice@idp.sso-lab.local",
    "profile": {"firstName": "Alice", "lastName": "Smith", "displayName": "Alice Smith"},
    "email": {"email": "alice@idp.sso-lab.local", "isEmailVerified": true},
    "passwordObject": {"password": "Test1234!", "changeRequired": false}
}')
echo "$ALICE_RESULT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('userId',''))" 2>/dev/null > /tmp/alice_uid.txt && log "  alice created!" || warn "  alice may already exist"

log "Creating test user: bob@idp.sso-lab.local ..."
BOB_RESULT=$(api_call POST "/management/v1/users/human/_import" '{
    "userName": "bob@idp.sso-lab.local",
    "profile": {"firstName": "Bob", "lastName": "Jones", "displayName": "Bob Jones"},
    "email": {"email": "bob@idp.sso-lab.local", "isEmailVerified": true},
    "passwordObject": {"password": "Test1234!", "changeRequired": false}
}')
echo "$BOB_RESULT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('userId',''))" 2>/dev/null > /tmp/bob_uid.txt && log "  bob created!" || warn "  bob may already exist"

# -----------------------------------------------------------
# Step 6: Activate test users
#   Zitadel creates users in INITIAL state requiring an init code.
#   We extract the codes from container logs and submit them.
# -----------------------------------------------------------
sleep 5  # Wait for Zitadel to generate init codes

activate_user() {
    local username="$1"
    local uid="$2"
    
    if [ -z "$uid" ]; then
        # Search for user ID if not provided
        uid=$(api_call POST "/management/v1/users/_search" '{}' | \
            python3 -c "import json,sys; [print(u['id']) for u in json.load(sys.stdin).get('result',[]) if u.get('userName','')=='$username']" 2>/dev/null | head -1)
    fi
    
    if [ -z "$uid" ]; then
        warn "Could not find UID for $username, skipping activation"
        return
    fi
    
    # Extract init code from Zitadel logs (visible in translation warnings)
    local code=$(docker logs sso-lab-idp 2>&1 | \
        grep "Code:" | grep "$username" | tail -1 | \
        python3 -c "import sys,re; m=re.search(r'Code:(\S+)', sys.stdin.read()); print(m.group(1) if m else '')" 2>/dev/null)
    
    if [ -z "$code" ]; then
        warn "Could not extract init code for $username"
        warn "You may need to activate manually via the console or check MailHog"
        return
    fi
    
    log "Activating $username with code ${code}..."
    
    python3 << PYEOF
import urllib.request, urllib.parse, http.cookiejar, json, re, ssl, hashlib, base64, secrets, sys

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE
base_url = "$BASE_URL"
CLIENT_ID = "${CLIENT_ID}"
init_code = "$code"

cj = http.cookiejar.CookieJar()
class NR(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*a,**kw): return None
opener = urllib.request.build_opener(
    urllib.request.HTTPSHandler(context=ssl_ctx),
    urllib.request.HTTPCookieProcessor(cj), NR())

def R(url, data=None, hdrs=None, follow=True):
    if not hdrs: hdrs = {}
    if isinstance(data, dict): data = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=data, headers=hdrs)
    o = opener if follow else opener
    try:
        resp = o.open(req, timeout=10); return resp.status, resp.read().decode(), resp.headers
    except Exception as e:
        return 0, str(e), {}

cv = secrets.token_urlsafe(32)
cc = base64.urlsafe_b64encode(hashlib.sha256(cv.encode()).digest()).rstrip(b'=').decode()
scope = "openid profile email"
redir = "https://app.sso-lab.local/callback"
url = (f"{base_url}/oauth/v2/authorize?client_id={CLIENT_ID}"
       f"&redirect_uri={urllib.parse.quote(redir)}"
       f"&response_type=code&scope={urllib.parse.quote(scope)}"
       f"&code_challenge={cc}&code_challenge_method=S256")

s,b,h = R(url)
csrf = re.search(r'name="gorilla\.csrf\.Token"[^>]*value="([^"]+)"', b)
aid = re.search(r'name="authRequestID"[^>]*value="([^"]*)"', b)
act = re.search(r'<form[^>]*action="([^"]*)"', b)
if not all([csrf, aid, act]):
    print(f"Failed to get login form", file=sys.stderr); sys.exit(1)

# Submit username
form = {"gorilla.csrf.Token": csrf.group(1), "loginname": "$username", "authRequestID": aid.group(1)}
s,b,h = R(base_url + act.group(1), form, {"Content-Type": "application/x-www-form-urlencoded"})
csrf2 = re.search(r'name="gorilla\.csrf\.Token"[^>]*value="([^"]+)"', b)
aid2 = re.search(r'name="authRequestID"[^>]*value="([^"]*)"', b)
act2 = re.search(r'<form[^>]*action="([^"]*)"', b)
uid_field = re.search(r'name="userID"[^>]*value="([^"]*)"', b)
pwset = re.search(r'name="passwordSet"[^>]*value="([^"]*)"', b)
orgid = re.search(r'name="orgID"[^>]*value="([^"]*)"', b)

if not csrf2 or not aid2 or not act2:
    print(f"Failed to get activation form", file=sys.stderr); sys.exit(1)

# Submit init form with code and password
form2 = {
    "gorilla.csrf.Token": csrf2.group(1),
    "authRequestID": aid2.group(1),
    "userID": uid_field.group(1) if uid_field else "",
    "passwordSet": pwset.group(1) if pwset else "false",
    "loginName": "$username",
    "orgID": orgid.group(1) if orgid else "",
    "code": init_code,
    "password": "Test1234!",
    "passwordconfirm": "Test1234!",
}
s,b,h = R(base_url + act2.group(1), form2, {"Content-Type": "application/x-www-form-urlencoded"}, follow=False)
title = re.search(r'<title>([^<]+)</title>', b[:5000] if isinstance(b,str) else '')
if title and 'Activated' in title.group(1):
    print("User activated successfully!")
else:
    print(f"Activation result: {title.group(1) if title else 'unknown'}", file=sys.stderr)
PYEOF
}

if [ -f /tmp/alice_uid.txt ] && [ -s /tmp/alice_uid.txt ]; then
    activate_user "alice@idp.sso-lab.local" "$(cat /tmp/alice_uid.txt)"
fi
if [ -f /tmp/bob_uid.txt ] && [ -s /tmp/bob_uid.txt ]; then
    activate_user "bob@idp.sso-lab.local" "$(cat /tmp/bob_uid.txt)"
fi

# -----------------------------------------------------------
# Summary
# -----------------------------------------------------------
echo ""
log "═══════════════════════════════════════"
log " Zitadel Setup Complete!"
log "═══════════════════════════════════════"
log ""
log "Issuer:           $BASE_URL"
log "Discovery URL:    $BASE_URL/.well-known/openid-configuration"
log "Client ID:        $CLIENT_ID"
log "Client Secret:    $CLIENT_SECRET"
log "Admin User:       $ADMIN_USERNAME / Admin123!"
log "Test User 1:      alice@idp.sso-lab.local / Test1234!"
log "Test User 2:      bob@idp.sso-lab.local / Test1234!"
log ""
log "Export these for the app service:"
log "  export ZITADEL_CLIENT_ID=$CLIENT_ID"
log "  export ZITADEL_CLIENT_SECRET=$CLIENT_SECRET"
