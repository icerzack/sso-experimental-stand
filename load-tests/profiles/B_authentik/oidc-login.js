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
const USERNAME = __ENV.TEST_USER || 'testuser';
const PASSWORD = __ENV.TEST_PASSWORD || 'testpass123';

const targetVU = parseInt(__ENV.TARGET_VU || '10');
const holdDuration = __ENV.HOLD_DURATION || '60s';

export const options = {
  stages: [
    { duration: '15s', target: targetVU },
    { duration: holdDuration, target: targetVU },
    { duration: '10s', target: 0 },
  ],
  thresholds: {
    errors: ['rate<0.5'],
  },
  insecureSkipTLSVerify: true,
};

/**
 * Authentik OIDC login via Flow Executor API.
 *
 * Flow (10 HTTP requests total):
 *   1. GET /authorize           → 302 (establishes session)
 *   2. GET flow executor        → identification challenge
 *   3. POST identification       → xak-flow-redirect
 *   4. GET flow executor         → password challenge
 *   5. POST password             → xak-flow-redirect (login done)
 *   6. GET flow executor         → confirm login complete
 *   7. GET /authorize            → 302 to consent flow
 *   8. GET consent page          → session context for consent
 *   9. GET consent executor      → code in redirect URL
 *  10. POST /token               → access_token
 *
 * Key insight: k6's http.cookieJar() persists cookies per VU,
 * so we must NOT use redirects:0 on steps where k6 should follow.
 * We explicitly control each step to measure latency precisely.
 */
export default function () {
  const startMs = Date.now();

  const authorizePath = `/application/o/authorize/?client_id=${CLIENT_ID}` +
    `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
    `&response_type=code` +
    `&scope=${encodeURIComponent('openid profile email')}`;
  const nextParam = encodeURIComponent(authorizePath);
  const flowUrl = `${BASE_URL}/api/v3/flows/executor/default-authentication-flow/?next=${nextParam}`;

  // ── Step 1: Initialize OAuth session ──
  const r1 = http.get(`${BASE_URL}${authorizePath}`, { redirects: 0 });
  if (r1.status !== 302 && r1.status !== 303) {
    errorRate.add(1);
    sleep(1);
    return;
  }

  // ── Step 2: Get identification challenge ──
  const r2 = http.get(flowUrl, { headers: { Accept: 'application/json' } });
  let ch;
  try { ch = JSON.parse(r2.body); } catch { errorRate.add(1); sleep(1); return; }
  if (ch.component !== 'ak-stage-identification') {
    errorRate.add(1);
    console.error(`Step2: expected identification, got ${ch.component}`);
    sleep(1);
    return;
  }

  // ── Step 3: Submit username ──
  const r3 = http.post(flowUrl, JSON.stringify({
    uid_field: USERNAME,
    component: 'ak-stage-identification',
  }), { headers: { 'Content-Type': 'application/json', Accept: 'application/json' } });

  // Step 3 returns xak-flow-redirect back to the same executor URL.
  // We need to GET it again to reach the password stage.

  // ── Step 4: Get password challenge ──
  const r4 = http.get(flowUrl, { headers: { Accept: 'application/json' } });
  try { ch = JSON.parse(r4.body); } catch { errorRate.add(1); sleep(1); return; }
  if (ch.component !== 'ak-stage-password') {
    errorRate.add(1);
    console.error(`Step4: expected password, got ${ch.component}`);
    sleep(1);
    return;
  }

  // ── Step 5: Submit password ──
  const r5 = http.post(flowUrl, JSON.stringify({
    password: PASSWORD,
    component: 'ak-stage-password',
  }), { headers: { 'Content-Type': 'application/json', Accept: 'application/json' } });

  // After password, we get xak-flow-redirect — need to confirm by reading executor once more

  // ── Step 6: Confirm login completion ──
  const r6 = http.get(flowUrl, { headers: { Accept: 'application/json' } });
  try { ch = JSON.parse(r6.body); } catch { /* ok if flow already completed */ }

  // ── Step 7: Re-authorize with authenticated session → get consent redirect ──
  const r7 = http.get(`${BASE_URL}${authorizePath}`, { redirects: 0 });
  if (r7.status !== 302 && r7.status !== 303) {
    errorRate.add(1);
    console.error(`Step7: expected 302, got ${r7.status}`);
    sleep(1);
    return;
  }

  let consentLoc = r7.headers.Location || r7.headers.location || '';
  if (!consentLoc) {
    errorRate.add(1);
    console.error('Step7: no Location header');
    sleep(1);
    return;
  }
  if (consentLoc.startsWith('/')) consentLoc = `${BASE_URL}${consentLoc}`;

  // Check if code is directly in the redirect (some configs skip consent)
  let code = null;
  const directCode = (consentLoc.match(/[?&]code=([^&#]+)/) || [])[1];
  if (directCode) {
    code = directCode;
  }

  if (!code) {
    // ── Step 8: Visit consent page to set up session context ──
    http.get(consentLoc, { headers: { Accept: 'application/json' } });

    // ── Step 9: Execute implicit consent flow to get auth code ──
    const consentExecUrl = `${BASE_URL}/api/v3/flows/executor/default-provider-authorization-implicit-consent/`;
    const r9 = http.get(consentExecUrl, { headers: { Accept: 'application/json' } });

    try {
      const c9 = JSON.parse(r9.body);
      if (c9.component === 'xak-flow-redirect' && c9.to) {
        const m = c9.to.match(/[?&]code=([^&#]+)/);
        if (m) code = m[1];
      }
    } catch { /* fall through */ }

    if (!code) {
      // Some versions require POST to consent executor
      const r9b = http.post(consentExecUrl, '{}', {
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      });
      try {
        const c9b = JSON.parse(r9b.body);
        if (c9b.component === 'xak-flow-redirect' && c9b.to) {
          const m = c9b.to.match(/[?&]code=([^&#]+)/);
          if (m) code = m[1];
        }
      } catch { /* fall through */ }
    }
  }

  if (!code) {
    errorRate.add(1);
    sleep(1);
    return;
  }

  // ── Step 10: Exchange code for tokens ──
  const tokenRes = http.post(`${BASE_URL}/application/o/token/`,
    `grant_type=authorization_code&client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}` +
    `&code=${encodeURIComponent(code)}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}`, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });

  const elapsed = Date.now() - startMs;
  loginLatency.add(elapsed);

  const success = check(tokenRes, {
    'token ok': (r) => r.status === 200,
    'has access_token': (r) => {
      try { return !!JSON.parse(r.body).access_token; } catch { return false; }
    },
  });

  errorRate.add(success ? 0 : 1);
  if (!success) {
    console.error(`Token fail: ${tokenRes.status} ${(tokenRes.body || '').substring(0, 120)}`);
  }

  sleep(Math.random() * 0.3);
}
