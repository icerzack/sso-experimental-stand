import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// ── Custom metrics ──
const errorRate = new Rate('errors');
const loginLatency = new Trend('login_latency', true);

// ── Configuration ──
const BASE_URL = __ENV.BASE_URL || 'https://idp.sso-lab.local';
const APP_URL = __ENV.APP_URL || 'https://app.sso-lab.local';
const CLIENT_ID = __ENV.CLIENT_ID || 'sso-test-app';
const CLIENT_SECRET = __ENV.CLIENT_SECRET || 'testpass123';
const REDIRECT_URI = __ENV.REDIRECT_URI || `${APP_URL}/callback`;
const USERNAME = __ENV.TEST_USER || 'alice';
const PASSWORD = __ENV.TEST_PASSWORD || 'password1';

const targetVU = parseInt(__ENV.TARGET_VU || '10');
const holdDuration = __ENV.HOLD_DURATION || '60s';

export const options = {
  stages: [
    { duration: '15s', target: targetVU },       // ramp-up
    { duration: holdDuration, target: targetVU }, // steady state
    { duration: '10s', target: 0 },               // ramp-down
  ],
  thresholds: {
    errors: ['rate<0.5'],
  },
  insecureSkipTLSVerify: true,
};

/**
 * Generate a cryptographically-adequate random string for state/nonce.
 * Authelia requires state ≥ 8 characters; we use 32 hex chars.
 */
function randomHex(len) {
  const chars = '0123456789abcdef';
  let s = '';
  for (let i = 0; i < len; i++) {
    s += chars[Math.floor(Math.random() * 16)];
  }
  return s;
}

/**
 * Authelia OIDC Authorization Code Flow via JSON API.
 *
 * Flow (5 HTTP requests typical):
 *
 *   1. POST /api/firstfactor          → JSON {username, password} → session cookies
 *   2. GET  /api/oidc/authorization   → 302 to /consent?id=<UUID>
 *   3. POST /api/oidc/consent         → JSON body → returns redirect_uri
 *   4. GET  <redirect_uri>            → follow redirect chain → extract code from callback URL
 *   5. POST /api/oidc/token           → exchange code for tokens (Basic auth)
 */
export default function () {
  const startMs = Date.now();

  const jar = http.cookieJar();
  const scope = encodeURIComponent('openid profile email');
  const redirectUri = encodeURIComponent(REDIRECT_URI);
  // State must be at least 8 chars — Authelia rejects short values as "too weak"
  const stateParam = `k6st${randomHex(28)}`;
  const nonceParam = `k6nc${randomHex(28)}`;

  // ── Step 1: Authenticate ──
  // We do this FIRST because the authorization endpoint will just redirect
  // unauthenticated users to the SPA login page, which is useless for API testing.
  const loginRes = http.post(
    `${BASE_URL}/api/firstfactor`,
    JSON.stringify({ username: USERNAME, password: PASSWORD }),
    {
      headers: { 'Content-Type': 'application/json' },
      redirects: 0,
    }
  );

  let loginOk = false;
  try {
    const body = JSON.parse(loginRes.body);
    loginOk = body.status === 'OK';
  } catch { /* fall through */ }

  if (!loginOk) {
    errorRate.add(1);
    console.error(`Login fail: ${loginRes.status} ${(loginRes.body || '').substring(0, 150)}`);
    sleep(1);
    return;
  }

  // ── Step 2: Request OIDC authorization (now authenticated) ──
  // This should produce a redirect to the consent page.
  const authUrl = `${BASE_URL}/api/oidc/authorization?client_id=${CLIENT_ID}` +
    `&redirect_uri=${redirectUri}` +
    `&response_type=code` +
    `&scope=${scope}` +
    `&state=${stateParam}` +
    `&nonce=${nonceParam}`;

  const authHeaders = http.get(authUrl, {
    redirects: 0,
  });

  // Extract consent ID from Location header
  let consentId = null;
  let code = null;
  const locationHeader = (authHeaders.headers['Location']
    || authHeaders.headers['location']
    || '').trim();

  // Check if already redirected with a code (auto-consent or pre-configured)
  if (locationHeader.includes('code=')) {
    const codeMatch = locationHeader.match(/[?&]code=([^&]+)/);
    if (codeMatch) {
      code = codeMatch[1];
    }
  } else if (locationHeader.includes('consent')) {
    const consentMatch = locationHeader.match(/[?&]id=([0-9a-f-]+)/i);
    if (consentMatch) {
      consentId = consentMatch[1];
    }
  }

  // If no direct redirect and no consent ID, try following one hop
  if (!consentId && !code && (authHeaders.status === 302 || authHeaders.status === 303)) {
    let nextLoc = locationHeader;
    if (nextLoc.startsWith('/')) nextLoc = BASE_URL + nextLoc;

    const nextHop = http.get(nextLoc, { redirects: 0 });
    const nextLocation = (nextHop.headers['Location'] || nextHop.headers['location'] || '').trim();

    if (nextLocation.includes('consent') && nextLocation.match(/[?&]id=([0-9a-f-]+)/i)) {
      consentId = nextLocation.match(/[?&]id=([0-9a-f-]+)/i)[1];
    } else if (nextLocation.includes('code=')) {
      const codeM = nextLocation.match(/[?&]code=([^&]+)/);
      if (codeM) code = codeM[1];
    }
  }

  // Still nothing — try full redirect following and check final URL
  if (!consentId && !code) {
    const authFollow = http.get(authUrl, { redirects: 5 });
    const finalUrl = authFollow.url || '';

    // Look for code in the final URL (could be on the app callback page)
    const cmFinal = finalUrl.match(/[?&]code=([^&#]+)/);
    if (cmFinal) {
      code = cmFinal[1];
    } else {
      // Check response body for error info
      const errInfo = (authFollow.body || '').substring(0, 200);
      errorRate.add(1);
      console.error(`No consent/code. Location: ${locationHeader.substring(0, 150)}, FinalURL: ${finalUrl.substring(0, 100)}, Body: ${errInfo}`);
      sleep(1);
      return;
    }
  }

  // ── Step 3: Accept consent (if needed) ──
  if (consentId && !code) {
    const consentRes = http.post(
      `${BASE_URL}/api/oidc/consent`,
      JSON.stringify({
        id: consentId,
        client_id: CLIENT_ID,
        consent: true,
        pre_configure: true,
      }),
      {
        headers: { 'Content-Type': 'application/json' },
        redirects: 0,
      }
    );

    // Parse redirect URI from consent response
    let authorizeRedirectUri = null;
    try {
      const body = JSON.parse(consentRes.body);
      if (body.data && body.data.redirect_uri) {
        authorizeRedirectUri = body.data.redirect_uri;
      }
    } catch { /* fall through */ }

    if (!authorizeRedirectUri) {
      errorRate.add(1);
      console.error(`Consent fail: ${consentRes.status} ${(consentRes.body || '').substring(0, 200)}`);
      sleep(1);
      return;
    }

    // ── Step 4: Follow redirect chain to extract authorization code ──
    const codeRedirect = http.get(authorizeRedirectUri, {
      redirects: 0,
    });

    const codeLocation = (codeRedirect.headers['Location'] || codeRedirect.headers['location'] || '').trim();
    const codeMatch = codeLocation.match(/[?&]code=([^&]+)/);
    if (codeMatch) {
      code = codeMatch[1];
    }

    // If still no code, try another hop
    if (!code && (codeRedirect.status === 302 || codeRedirect.status === 303)) {
      let nextLoc = codeLocation;
      if (nextLoc.startsWith('/')) nextLoc = BASE_URL + nextLoc;

      const nextHop = http.get(nextLoc, { redirects: 0 });
      const nl2 = (nextHop.headers['Location'] || nextHop.headers['location'] || '').trim();
      const cm2 = nl2.match(/[?&]code=([^&]+)/);
      if (cm2) code = cm2[1];
    }
  }

  if (!code) {
    errorRate.add(1);
    console.error(`No authorization code obtained`);
    sleep(1);
    return;
  }

  // ── Step 5: Exchange code for tokens ──
  const tokenRes = exchangeCode(code, redirectUri);

  const elapsed = Date.now() - startMs;
  loginLatency.add(elapsed);

  const success = checkTokenResponse(tokenRes);
  errorRate.add(success ? 0 : 1);

  if (!success) {
    console.error(`Token fail: ${tokenRes.status} ${(tokenRes.body || '').substring(0, 150)}`);
  }

  sleep(Math.random() * 0.3);
}

/**
 * Exchange authorization code for tokens using client_secret_post.
 * (Authelia supports both client_secret_basic and client_secret_post;
 *  we use post because k6 doesn't provide btoa() for Basic auth headers.)
 */
function exchangeCode(code, redirectUri) {
  return http.post(
    `${BASE_URL}/api/oidc/token`,
    `grant_type=authorization_code` +
    `&code=${encodeURIComponent(code)}` +
    `&redirect_uri=${redirectUri}` +
    `&client_id=${encodeURIComponent(CLIENT_ID)}` +
    `&client_secret=${encodeURIComponent(CLIENT_SECRET)}`,
    {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    }
  );
}

/**
 * Validate token response has both access_token and id_token.
 */
function checkTokenResponse(tokenRes) {
  return check(tokenRes, {
    'token ok': (r) => r.status === 200,
    'has access_token': (r) => {
      try { return !!JSON.parse(r.body).access_token; }
      catch { return false; }
    },
    'has id_token': (r) => {
      try { return !!JSON.parse(r.body).id_token; }
      catch { return false; }
    },
  });
}
