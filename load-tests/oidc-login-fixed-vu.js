import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// ── Custom metrics ──
const errorRate = new Rate('errors');
const loginLatency = new Trend('login_latency', true);

// ── Configuration ──
const BASE_URL = __ENV.BASE_URL || 'https://idp.sso-lab.local';
const APP_URL = __ENV.APP_URL || 'https://app.sso-lab.local';
const REALM = __ENV.REALM || 'sso-lab';
const CLIENT_ID = __ENV.CLIENT_ID || 'sso-test-app';
const CLIENT_SECRET = __ENV.CLIENT_SECRET || 'testpass123';
const REDIRECT_URI = __ENV.REDIRECT_URI || `${APP_URL}/callback`;
const USERNAME = __ENV.TEST_USER || 'testuser';
const PASSWORD = __ENV.TEST_PASSWORD || 'testpass123';

// Single-stage test: ramp to TARGET_VU, hold for HOLD_DURATION
const targetVU = parseInt(__ENV.TARGET_VU || '10');
const holdDuration = __ENV.HOLD_DURATION || '60s';

export const options = {
  stages: [
    { duration: '15s', target: targetVU },  // ramp-up
    { duration: holdDuration, target: targetVU },  // steady state
    { duration: '10s', target: 0 },  // ramp-down
  ],
  thresholds: {
    errors: ['rate<0.5'],
  },
  insecureSkipTLSVerify: true,
};

function fixScheme(url) {
  return url.replace(/^http:\/\//, 'https://');
}

export default function () {
  const startMs = Date.now();

  const stateParam = `k6_${__VU}_${__ITER}`;
  const authURL = `${BASE_URL}/realms/${REALM}/protocol/openid-connect/auth` +
    `?client_id=${CLIENT_ID}` +
    `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
    `&response_type=code` +
    `&scope=${encodeURIComponent('openid profile email')}` +
    `&state=${stateParam}`;

  // Step 1: Initiate OIDC auth (follow redirects to login page)
  const authRes = http.get(authURL, { redirects: 5 });
  if (authRes.status !== 200) {
    errorRate.add(1);
    console.error(`Step1 fail: ${authRes.status}`);
    sleep(1);
    return;
  }

  // Step 2: Submit credentials
  const actionMatch = authRes.body.match(/action="([^"]*)"/i);
  if (!actionMatch) {
    errorRate.add(1);
    console.error('Step2 fail: no form action');
    sleep(1);
    return;
  }

  let formAction = actionMatch[1].replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"');
  formAction = fixScheme(formAction);

  const loginRes = http.post(formAction,
    `username=${USERNAME}&password=${PASSWORD}&credentialId=&login=Sign+In`, {
    redirects: 0,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });

  // Step 3: Follow redirects to extract authorization code
  let code = null;
  let currentRes = loginRes;

  for (let i = 0; i < 10; i++) {
    if (currentRes.status === 302 || currentRes.status === 303) {
      let loc = currentRes.headers.Location;
      if (!loc) break;

      const codeInRedirect = loc.match(/[?&]code=([^&#]+)/);
      if (codeInRedirect) {
        code = codeInRedirect[1];
        break;
      }

      loc = fixScheme(loc);
      currentRes = http.get(loc, { redirects: 0 });
    } else {
      break;
    }
  }

  if (!code) {
    errorRate.add(1);
    console.error('Step3 fail: no code');
    sleep(1);
    return;
  }

  // Step 4: Exchange code for tokens
  const tokenURL = `${BASE_URL}/realms/${REALM}/protocol/openid-connect/token`;
  const tokenRes = http.post(tokenURL,
    `grant_type=authorization_code&client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}` +
    `&code=${encodeURIComponent(code)}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}`, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });

  const elapsed = Date.now() - startMs;
  loginLatency.add(elapsed);

  const success = check(tokenRes, {
    'token ok': (r) => r.status === 200,
    'has token': (r) => { try { return !!JSON.parse(r.body).access_token; } catch { return false; } },
  });

  errorRate.add(success ? 0 : 1);
  if (!success) {
    console.error(`Token fail: ${tokenRes.status} ${(tokenRes.body || '').substring(0, 150)}`);
  }

  sleep(Math.random() * 0.3);
}
