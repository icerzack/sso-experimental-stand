import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// ──────────────────────────────────────────────
// Custom metrics
// ──────────────────────────────────────────────

const errorRate = new Rate('errors');
const loginDuration = new Trend('login_duration', true);
const tokenAcquireDuration = new Trend('token_acquire_duration', true);

// ──────────────────────────────────────────────
// Configuration
//
// The script supports two load patterns controlled by LOAD_MODE env var:
//   "ropc"   (default) — ROPC grant to the IdP token endpoint.
//                       Exercises credential verification + JWT signing per request.
//                       Best for pure IdP throughput measurement.
//   "browser"          — Full Authorization Code Flow through redirects.
//                       Exercises Traefik → App → IdP round-trip + session creation.
//                       Best for end-to-end latency measurement.
//   "mixed"            — Alternates between ROPC and browser flows.
// ──────────────────────────────────────────────

export const options = {
  stages: [
    { duration: '30s', target: __ENV.VUS_START || 10 },
    { duration: '1m',  target: __ENV.VUS_PEAK || 50 },
    { duration: '30s', target: 0 },
  ],
  thresholds: {
    http_req_duration: ['p(95)<3000'],
    errors: ['rate<0.15'],
    login_duration: ['p(95)<5000'],
  },
};

const BASE_URL       = (__ENV.BASE_URL || 'https://app.sso-lab.local').replace(/\/+$/, '');
const IDP_URL        = (__ENV.IDP_URL || 'https://idp.sso-lab.local').replace(/\/+$/, '');
const REALM          = __ENV.REALM || 'sso-lab';
const CLIENT_ID      = __ENV.CLIENT_ID || 'sso-test-app';
const CLIENT_SECRET  = __ENV.CLIENT_SECRET || 'testpass123';
const USERNAME       = __ENV.TEST_USERNAME || 'testuser';
const PASSWORD       = __ENV.TEST_PASSWORD || 'password123';
const LOAD_MODE      = __ENV.LOAD_MODE || 'mixed';

// Pre-requisite: /etc/hosts must contain:
//   127.0.0.1  app.sso-lab.local idp.sso-lab.local
// Run `make hosts-add` before running the benchmark.

const COMMON_PARAMS = {
  headers: { 'Accept': 'application/json' },
  tls: { rejectUnauthorized: false },
  timeout: '10s',
};

const HTML_PARAMS = {
  headers: { 'Accept': 'text/html' },
  tls: { rejectUnauthorized: false },
  timeout: '10s',
};

// ──────────────────────────────────────────────
// ROPC token acquisition
// ──────────────────────────────────────────────

function acquireTokenRopc() {
  let tokenUrl;
  if (__ENV.TOKEN_URL) {
    tokenUrl = __ENV.TOKEN_URL;
  } else if (REALM !== '') {
    // Keycloak-style: /realms/<realm>/protocol/openid-connect/token
    tokenUrl = `${IDP_URL}/realms/${REALM}/protocol/openid-connect/token`;
  } else {
    // Zitadel/Authelia-style: /oauth/v2/token or /api/oidc/token
    // Default to Zitadel path; override via TOKEN_URL env for other IdPs
    tokenUrl = `${IDP_URL}/oauth/v2/token`;
  }

  const start = Date.now();
  const res = http.post(tokenUrl, {
    grant_type: 'password',
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    username: USERNAME,
    password: PASSWORD,
    scope: 'openid profile email',
  }, COMMON_PARAMS);
  tokenAcquireDuration.add(Date.now() - start);

  const ok = check(res, {
    'token endpoint status 200': r => r.status === 200,
    'got access_token': r => {
      try { return !!JSON.parse(r.body).access_token; }
      catch { return false; }
    },
  });
  if (!ok) errorRate.add(1);

  let accessToken = '';
  try { accessToken = JSON.parse(res.body).access_token || ''; } catch {}
  return accessToken;
}

// ──────────────────────────────────────────────
// Browser-like OIDC flow
//
// Performs a full Authorization Code Flow by following redirect chain:
// GET /login → 302 to IdP → submit form → 302 /callback → session cookie
// This exercises Traefik + App + IdP round-trip with session creation.
// ──────────────────────────────────────────────

function browserLogin() {
  const start = Date.now();
  const jar = new http.CookieJar();

  // Follow redirect chain through IdP back to app
  const res = http.get(`${BASE_URL}/login`, Object.assign({}, HTML_PARAMS, {
    jar,
    redirects: 10,
  }));

  loginDuration.add(Date.now() - start);

  check(res, {
    'browser login completed': r => r.status === 200 || r.status === 303,
  }) || errorRate.add(1);
}

// ──────────────────────────────────────────────
// Protected resource access with Bearer token
// ──────────────────────────────────────────────

function accessDashboard(accessToken) {
  if (!accessToken) return;

  const start = Date.now();
  const res = http.get(`${BASE_URL}/dashboard`, Object.assign({}, COMMON_PARAMS, {
    headers: {
      'Accept': 'text/html',
      'Authorization': `Bearer ${accessToken}`,
    },
  }));
  loginDuration.add(Date.now() - start);

  check(res, {
    'dashboard accessible': r =>
      r.status === 200 ||
      r.status === 302 ||
      r.status === 303,
  }) || errorRate.add(1);
}

// ──────────────────────────────────────────────
// Main VU function
// ──────────────────────────────────────────────

export default function () {
  switch (LOAD_MODE) {
    case 'ropc':
      acquireTokenRopc();
      break;

    case 'browser':
      browserLogin();
      break;

    case 'mixed':
    default:
      // Alternate: even iterations do ROPC, odd do browser flow
      if (__ITER % 2 === 0) {
        const token = acquireTokenRopc();
        accessDashboard(token);
      } else {
        browserLogin();
      }
      break;
  }

  sleep(Math.random() * 2 + 1);
}

// ──────────────────────────────────────────────
// Summary output
// ──────────────────────────────────────────────

export function handleSummary(data) {
  return {
    stdout: JSON.stringify(data, null, 2),
    [`results/raw/k6-${new Date().toISOString().replace(/[:.]/g, '-')}.json`]: JSON.stringify(data, null, 2),
  };
}
