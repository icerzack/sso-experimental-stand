import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Rate } from 'k6/metrics';

const CONCURRENCY = parseInt(__ENV.CONCURRENCY || '20', 10);
const WARM_UP_S = parseInt(__ENV.WARM_UP_S || '30', 10);
const STEADY_STATE_S = parseInt(__ENV.STEADY_STATE_S || '60', 10);
const RAMP_DOWN_S = parseInt(__ENV.RAMP_DOWN_S || String(WARM_UP_S), 10);

export const options = {
  stages: [
    { duration: `${WARM_UP_S}s`, target: CONCURRENCY },
    { duration: `${STEADY_STATE_S}s`, target: CONCURRENCY },
    { duration: `${RAMP_DOWN_S}s`, target: 0 },
  ],
  thresholds: (__ENV.DISABLE_THRESHOLDS === '1')
    ? {}
    : {
        login_e2e_ms: ['p(95)<2000'],
        http_req_failed: ['rate<0.1'],
      },
};

const BASE_URL = __ENV.BASE_URL || 'http://saml-sp.localhost';
const USERNAME = __ENV.USERNAME || 'testuser1';
const PASSWORD = __ENV.PASSWORD || 'password123';

const loginE2E = new Trend('login_e2e_ms', true);
const redirectCountTrend = new Trend('redirect_count', true);
const protocolPayloadSizeBytes = new Trend('token_assertion_size_bytes', true);
const protocolErrors = new Rate('protocol_error_rate');

const KEYCLOAK_URL = __ENV.KEYCLOAK_URL || 'http://keycloak.localhost';
const MAX_REDIRECTS = parseInt(__ENV.MAX_REDIRECTS || '15', 10);

function safeClearCookies() {
  const jar = http.cookieJar();
  try {
    jar.clear(BASE_URL);
    jar.clear(KEYCLOAK_URL);
  } catch (_) {
    // If clear() isn't available in the runtime, we still proceed.
    // The experiment runner should prefer fresh VUs per run for strict cold runs.
  }
}

function extractFirstMatch(text, regex) {
  const m = text.match(regex);
  return m ? m[1] : null;
}

function extractFormAction(html) {
  return extractFirstMatch(html, /<form[^>]*action="([^"]+)"/i);
}

function extractInputValue(html, name) {
  const re = new RegExp(`<input[^>]*name="${name}"[^>]*value="([^"]*)"`, 'i');
  return extractFirstMatch(html, re);
}

function isRedirect(res) {
  return res && (res.status === 301 || res.status === 302 || res.status === 303 || res.status === 307 || res.status === 308);
}

function resolveUrl(baseUrl, location) {
  if (!location) return location;
  // Keycloak login pages often HTML-escape '&' inside form actions.
  location = String(location).replaceAll('&amp;', '&');

  const base = String(baseUrl || '');
  const originMatch = base.match(/^(https?:\/\/[^/]+)/i);
  const origin = originMatch ? originMatch[1] : '';

  const keycloakOriginMatch = String(KEYCLOAK_URL || '').match(/^(https?:\/\/[^/]+)/i);
  const keycloakOrigin = keycloakOriginMatch ? keycloakOriginMatch[1] : '';

  // If we already have an absolute URL, normalize internal container hosts back to external hosts.
  if (location.startsWith('http://') || location.startsWith('https://')) {
    if (keycloakOrigin && location.includes('://keycloak:')) {
      return location.replace(/^https?:\/\/keycloak(?::\d+)?/i, keycloakOrigin);
    }
    if (location.includes('://saml-sp:') || location.includes('://oidc-rp:')) {
      return location
        .replace(/^https?:\/\/saml-sp(?::\d+)?/i, origin)
        .replace(/^https?:\/\/oidc-rp(?::\d+)?/i, origin);
    }
    return location;
  }
  const pathPart = base.replace(origin, '').split('?')[0].split('#')[0] || '/';
  if (location.startsWith('/')) return `${origin}${location}`;
  // Resolve relative to the current URL path (directory), not to origin root.
  const dir = pathPart.endsWith('/') ? pathPart : pathPart.substring(0, pathPart.lastIndexOf('/') + 1);
  return `${origin}${dir}${location}`;
}

function followRedirects(res, currentUrl, params, maxRedirects) {
  let redirects = 0;
  while (isRedirect(res) && redirects < maxRedirects) {
    const loc = res.headers.Location;
    if (!loc) {
      break;
    }
    const nextUrl = resolveUrl(currentUrl, loc);
    res = http.get(nextUrl, Object.assign({}, params, { redirects: 0 }));
    currentUrl = nextUrl;
    redirects++;
  }
  return { res, redirects, currentUrl };
}

function maybeHandleSamlPostBinding(res, currentUrl, params) {
  // After Keycloak login, SAML flow often returns an auto-submitting HTML form:
  // <form action=".../callback" method="post"><input name="SAMLResponse" value="..."/>
  if (!res || res.status !== 200 || !res.body) {
    return null;
  }
  if (!res.body.includes('SAMLResponse')) {
    return null;
  }
  const action = extractFormAction(res.body);
  const samlResponse = extractInputValue(res.body, 'SAMLResponse');
  const relayState = extractInputValue(res.body, 'RelayState');
  if (!action || !samlResponse) {
    return null;
  }
  protocolPayloadSizeBytes.add(samlResponse.length);
  const payload = relayState ? { SAMLResponse: samlResponse, RelayState: relayState } : { SAMLResponse: samlResponse };
  const postUrl = resolveUrl(currentUrl, action);
  return http.post(postUrl, payload, Object.assign({}, params, { redirects: 0 }));
}

export default function () {
  // Cold run: best-effort cookie clearing to avoid VU-local session reuse.
  safeClearCookies();

  const params = { redirects: 0 };
  const started = Date.now();

  // Step 1: Access protected endpoint (will redirect to app login)
  let currentUrl = `${BASE_URL}/protected`;
  let res = http.get(currentUrl, params);

  // Step 2+: Follow redirects (app -> keycloak -> callback -> protected)
  let totalRedirects = 0;

  // Follow until we reach a non-redirect response.
  let out = followRedirects(res, currentUrl, params, MAX_REDIRECTS);
  res = out.res;
  currentUrl = out.currentUrl;
  totalRedirects += out.redirects;

  // If we got the Keycloak login page, submit credentials.
  if (res.status === 200 && res.body && res.body.includes('login') && res.body.includes('username')) {
    const formAction = extractFormAction(res.body);
    if (!formAction) {
      protocolErrors.add(1);
    } else {
      const postUrl = resolveUrl(currentUrl, formAction);
      res = http.post(postUrl, { username: USERNAME, password: PASSWORD }, params);
      out = followRedirects(res, postUrl, params, MAX_REDIRECTS);
      res = out.res;
      currentUrl = out.currentUrl;
      totalRedirects += out.redirects;
    }
  }

  // SAML: handle POST binding form if present (then follow redirects to /protected).
  const maybePosted = maybeHandleSamlPostBinding(res, currentUrl, params);
  if (maybePosted) {
    res = maybePosted;
    out = followRedirects(res, currentUrl, params, MAX_REDIRECTS);
    res = out.res;
    currentUrl = out.currentUrl;
    totalRedirects += out.redirects;
  }

  // If we still ended up with redirects (e.g. app redirects to /protected), follow them.
  out = followRedirects(res, currentUrl, params, MAX_REDIRECTS);
  res = out.res;
  currentUrl = out.currentUrl;
  totalRedirects += out.redirects;

  const finished = Date.now();
  loginE2E.add(finished - started);
  redirectCountTrend.add(totalRedirects);

  const ok = check(res, {
    'protected page accessible': (r) => r && r.status === 200,
    'user info displayed': (r) => r && r.body && r.body.includes(USERNAME),
  });
  protocolErrors.add(ok ? 0 : 1);

  sleep(1);
}

export function handleSummary(data) {
  if (!__ENV.SUMMARY_PATH) {
    return {};
  }
  return {
    [__ENV.SUMMARY_PATH]: JSON.stringify(data, null, 2),
  };
}

