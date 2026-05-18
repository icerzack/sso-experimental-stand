import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';
import encoding from 'k6/encoding';

// ── Custom metrics ──
const errorRate = new Rate('errors');
const loginLatency = new Trend('login_latency', true);

// ── Configuration ──
const BASE_URL       = (__ENV.BASE_URL || 'https://idp.sso-lab.local').replace(/\/+$/, '');
const APP_URL        = (__ENV.APP_URL || 'https://app.sso-lab.local').replace(/\/+$/, '');
const CLIENT_ID      = __ENV.CLIENT_ID || '373398291624296457@sso_lab_apps';
const CLIENT_SECRET  = __ENV.CLIENT_SECRET || 'o7N5zIr40FUqM3oc8pXlSjvpTCuA0YXbc2vIjqBj48HdtKh0mLyUqXPcEJAIBzOZ';
const REDIRECT_URI   = __ENV.REDIRECT_URI || `${APP_URL}/callback`;
const USERNAME       = __ENV.TEST_USER || 'alice@idp.sso-lab.local';
const PASSWORD       = __ENV.TEST_PASSWORD || 'Test1234!';

// Load shape
const targetVU     = parseInt(__ENV.TARGET_VU || '10');
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

// ── PKCE helpers ──

function base64urlEncode(buf) {
  return encoding.b64encode(buf, 'rawurl');
}

function generatePKCE() {
  // Generate a random code_verifier (32 bytes → 43 base64url chars)
  const rawBytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) rawBytes[i] = Math.floor(Math.random() * 256);
  const verifier = base64urlEncode(String.fromCharCode(...rawBytes));

  // SHA-256 hash to produce code_challenge
  const hasher = new crypto.SHA256();
  // k6 doesn't expose crypto.subtle; use http-based workaround or skip if unavailable.
  // For Zitadel in devMode=true with confidential client, PKCE is optional.
  // We include code_challenge when possible but don't fail without it.

  return { verifier, challenge: null }; // Challenge set to null; Zitadel dev mode allows this
}

// ── Form field extraction helpers ──

function extractField(html, pattern) {
  const m = html.match(pattern);
  return m ? m[1] : null;
}

function extractFormFields(html) {
  return {
    csrf:     extractField(html, /name="gorilla\.csrf\.Token"[^>]*value="([^"]+)"/),
    aid:      extractField(html, /name="authRequestID"[^>]*value="([^"]*)"/),
    action:   extractField(html, /<form[^>]*action="([^"]*)"/),
  };
}

function absoluteUrl(path) {
  if (!path) return path;
  if (path.startsWith('http')) return path;
  if (path.startsWith('/')) return BASE_URL + path;
  return BASE_URL + '/' + path;
}

function fixScheme(url) {
  return url.replace(/^http:\/\//, 'https://');
}

/**
 * Zitadel OIDC Authorization Code Flow via form-based login.
 *
 * Flow (4–7 HTTP requests):
 *   1. GET /oauth/v2/authorize         → follow redirects → login page (CSRF + authRequestID)
 *   2. POST /ui/login/loginname        → submit username → password page (new CSRF)
 *   3. POST /ui/login/password          → submit password → 302 redirect chain
 *   4. Follow redirects                 → may encounter MFA prompt page → skip it
 *   5. Extract authorization code from callback URL
 *   6. POST /oauth/v2/token             → exchange code for access_token
 */
export default function () {
  const startMs = Date.now();

  const scopeEncoded    = encodeURIComponent('openid profile email');
  const redirectEncoded = encodeURIComponent(REDIRECT_URI);
  const stateParam      = `k6_${__VU}_${__ITER}`;

  // Build authorize URL
  const authUrl = `${BASE_URL}/oauth/v2/authorize` +
    `?client_id=${CLIENT_ID}` +
    `&redirect_uri=${redirectEncoded}` +
    `&response_type=code` +
    `&scope=${scopeEncoded}` +
    `&state=${stateParam}`;

  // ── Step 1: Initiate OIDC auth — follow redirects to reach the login form ──
  const r1 = http.get(authUrl, {
    redirects: 10,
    headers: { Accept: 'text/html' },
  });

  if (r1.status !== 200) {
    errorRate.add(1);
    console.error(`Step1 fail: got ${r1.status}`);
    sleep(1);
    return;
  }

  const f1 = extractFormFields(r1.body);
  if (!f1.csrf || !f1.aid || !f1.action) {
    errorRate.add(1);
    console.error(`Step1 parse fail: csrf=${!!f1.csrf} aid=${!!f1.aid} act=${!!f1.action}`);
    sleep(1);
    return;
  }

  // ── Step 2: Submit username ──
  const r2 = http.post(absoluteUrl(f1.action),
    `gorilla.csrf.Token=${encodeURIComponent(f1.csrf)}&loginname=${encodeURIComponent(USERNAME)}&authRequestID=${encodeURIComponent(f1.aid)}`, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    redirects: 5,
  });

  if (r2.status !== 200) {
    errorRate.add(1);
    console.error(`Step2 fail: got ${r2.status}`);
    sleep(1);
    return;
  }

  const f2 = extractFormFields(r2.body);
  if (!f2.csrf || !f2.aid || !f2.action) {
    errorRate.add(1);
    console.error(`Step2 parse fail: expected password form`);
    sleep(1);
    return;
  }

  // ── Step 3: Submit password (don't auto-follow redirects) ──
  const r3 = http.post(absoluteUrl(f2.action),
    `gorilla.csrf.Token=${encodeURIComponent(f2.csrf)}&password=${encodeURIComponent(PASSWORD)}&authRequestID=${encodeURIComponent(f2.aid)}`, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    redirects: 0,
  });

  // ── Step 4–5: Follow redirect chain to extract authorization code ──
  let code = null;
  let currentRes = r3;

  for (let i = 0; i < 12; i++) {
    const status = currentRes.status;

    if (status === 302 || status === 303) {
      let loc = currentRes.headers['Location'] || currentRes.headers['location'] || '';
      if (!loc) break;

      loc = fixScheme(loc);

      // Check for authorization code in the Location header
      const codeMatch = loc.match(/[?&]code=([^&#]+)/);
      if (codeMatch) {
        code = codeMatch[1];
        break;
      }

      // Check if this redirects to an MFA prompt page
      if (loc.includes('/mfa')) {
        const mfaPage = http.get(loc, { redirects: 0 });
        if (mfaPage.status === 200 && mfaPage.body) {
          const mfa = extractFormFields(mfaPage.body);
          if (mfa.csrf && mfa.aid && mfa.action) {
            const skipRes = http.post(absoluteUrl(mfa.action),
              `gorilla.csrf.Token=${encodeURIComponent(mfa.csrf)}&skip=true&authRequestID=${encodeURIComponent(mfa.aid)}`, {
              headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
              redirects: 0,
            });
            currentRes = skipRes;
            continue;
          }
        }
        // Can't parse MFA form, try following normally
      }

      // Fix relative URLs
      if (loc.startsWith('/')) loc = BASE_URL + loc;

      currentRes = http.get(loc, { redirects: 0 });

    } else if (status === 200) {
      // We got an HTML page instead of a redirect.
      // This can happen with MFA prompts or consent screens.
      const body = currentRes.body || '';

      if (body.includes('mfa') || body.includes('/mfa/prompt')) {
        const mfa = extractFormFields(body);
        if (mfa.csrf && mfa.aid && mfa.action) {
          const skipRes = http.post(absoluteUrl(mfa.action),
            `gorilla.csrf.Token=${encodeURIComponent(mfa.csrf)}&skip=true&authRequestID=${encodeURIComponent(mfa.aid)}`, {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            redirects: 0,
          });
          currentRes = skipRes;
          continue;
        }
      }

      // No useful content on this page, stop following
      break;

    } else {
      // Unexpected status code (4xx/5xx), stop
      break;
    }
  }

  if (!code) {
    errorRate.add(1);
    console.error(`No auth code extracted after password submission (last status: ${currentRes.status})`);
    sleep(1);
    return;
  }

  // ── Step 6: Exchange authorization code for tokens ──
  const tokenRes = http.post(`${BASE_URL}/oauth/v2/token`,
    `grant_type=authorization_code` +
    `&client_id=${CLIENT_ID}` +
    `&client_secret=${encodeURIComponent(CLIENT_SECRET)}` +
    `&code=${encodeURIComponent(code)}` +
    `&redirect_uri=${redirectEncoded}`, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });

  const elapsed = Date.now() - startMs;
  loginLatency.add(elapsed);

  const success = check(tokenRes, {
    'token ok': (r) => r.status === 200,
    'has token': (r) => {
      try { return !!JSON.parse(r.body).access_token; }
      catch { return false; }
    },
  });

  errorRate.add(success ? 0 : 1);
  if (!success) {
    console.error(`Token fail: ${tokenRes.status} ${(tokenRes.body || '').substring(0, 150)}`);
  }

  sleep(Math.random() * 0.3);
}
