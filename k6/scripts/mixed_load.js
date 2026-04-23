import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Rate } from 'k6/metrics';

const CONCURRENCY = parseInt(__ENV.CONCURRENCY || '50', 10);
const WARM_UP_S = parseInt(__ENV.WARM_UP_S || '60', 10);
const STEADY_STATE_S = parseInt(__ENV.STEADY_STATE_S || '120', 10);
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
const sessionReuseMs = new Trend('session_reuse_ms', true);
const protocolErrors = new Rate('protocol_error_rate');

const KEYCLOAK_URL = __ENV.KEYCLOAK_URL || 'http://keycloak.localhost';
const MAX_REDIRECTS = parseInt(__ENV.MAX_REDIRECTS || '15', 10);

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
  const base = String(baseUrl || '');
  const originMatch = base.match(/^(https?:\/\/[^/]+)/i);
  const origin = originMatch ? originMatch[1] : '';
  location = String(location).replaceAll('&amp;', '&');

  const keycloakOriginMatch = String(KEYCLOAK_URL || '').match(/^(https?:\/\/[^/]+)/i);
  const keycloakOrigin = keycloakOriginMatch ? keycloakOriginMatch[1] : '';

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
  const payload = relayState ? { SAMLResponse: samlResponse, RelayState: relayState } : { SAMLResponse: samlResponse };
  const postUrl = resolveUrl(currentUrl, action);
  return http.post(postUrl, payload, Object.assign({}, params, { redirects: 0 }));
}

function safeClearCookies(url) {
  const jar = http.cookieJar();
  try {
    jar.clear(url);
  } catch (_) {
    // ignore
  }
}

function doColdLogin() {
  safeClearCookies(BASE_URL);
  safeClearCookies(KEYCLOAK_URL);

  const params = { redirects: 0 };
  const started = Date.now();

  let currentUrl = `${BASE_URL}/protected`;
  let res = http.get(currentUrl, params);
  let totalRedirects = 0;

  let out = followRedirects(res, currentUrl, params, MAX_REDIRECTS);
  res = out.res;
  currentUrl = out.currentUrl;
  totalRedirects += out.redirects;

  if (res.status === 200 && res.body && res.body.includes('login') && res.body.includes('username')) {
    const formAction = extractFormAction(res.body);
    if (formAction) {
      const postUrl = resolveUrl(currentUrl, formAction);
      res = http.post(postUrl, { username: USERNAME, password: PASSWORD }, params);
      out = followRedirects(res, postUrl, params, MAX_REDIRECTS);
      res = out.res;
      currentUrl = out.currentUrl;
      totalRedirects += out.redirects;
    }
  }

  const maybePosted = maybeHandleSamlPostBinding(res, currentUrl, params);
  if (maybePosted) {
    res = maybePosted;
    out = followRedirects(res, currentUrl, params, MAX_REDIRECTS);
    res = out.res;
    currentUrl = out.currentUrl;
    totalRedirects += out.redirects;
  }

  out = followRedirects(res, currentUrl, params, MAX_REDIRECTS);
  res = out.res;
  currentUrl = out.currentUrl;
  totalRedirects += out.redirects;

  loginE2E.add(Date.now() - started);
  redirectCountTrend.add(totalRedirects);

  const ok = check(res, { 'cold: protected accessible': (r) => r && r.status === 200 });
  protocolErrors.add(ok ? 0 : 1);
}

function doWarmIdpLogin(data) {
  safeClearCookies(BASE_URL);

  const jar = http.cookieJar();
  if (data && data.keycloakCookies) {
    for (const [name, values] of Object.entries(data.keycloakCookies)) {
      if (!Array.isArray(values) || values.length < 1) continue;
      jar.set(KEYCLOAK_URL, name, values[0]);
    }
  }

  const params = { redirects: 0 };
  const started = Date.now();

  let currentUrl = `${BASE_URL}/protected`;
  let res = http.get(currentUrl, params);
  let totalRedirects = 0;

  let out = followRedirects(res, currentUrl, params, MAX_REDIRECTS);
  res = out.res;
  currentUrl = out.currentUrl;
  totalRedirects += out.redirects;

  const maybePosted = maybeHandleSamlPostBinding(res, currentUrl, params);
  if (maybePosted) {
    res = maybePosted;
    out = followRedirects(res, currentUrl, params, MAX_REDIRECTS);
    res = out.res;
    currentUrl = out.currentUrl;
    totalRedirects += out.redirects;
  }

  out = followRedirects(res, currentUrl, params, MAX_REDIRECTS);
  res = out.res;
  currentUrl = out.currentUrl;
  totalRedirects += out.redirects;

  loginE2E.add(Date.now() - started);
  redirectCountTrend.add(totalRedirects);

  const ok = check(res, { 'warm: protected accessible': (r) => r && r.status === 200 });
  protocolErrors.add(ok ? 0 : 1);
}

function doSessionReuse(data) {
  const started = Date.now();
  let res = http.get(`${BASE_URL}/protected`, Object.assign({}, { redirects: 0 }, { cookies: data.appCookies || {} }));
  const out = followRedirects(res, Object.assign({}, { redirects: 0 }, { cookies: data.appCookies || {} }), 5);
  res = out.res;
  sessionReuseMs.add(Date.now() - started);
  const ok = check(res, { 'session: no redirects': () => out.redirects === 0 });
  protocolErrors.add(ok ? 0 : 1);
}

// Mix of scenarios: 30% cold login, 40% warm IdP login, 30% session reuse
export function setup() {
  // Establish a Keycloak+app session once so we can reuse cookies for warm/session slices.
  const jar = http.cookieJar();
  const params = { redirects: 0 };

  let res = http.get(`${BASE_URL}/protected`, params);
  let currentUrl = `${BASE_URL}/protected`;
  let out = followRedirects(res, currentUrl, params, MAX_REDIRECTS);
  res = out.res;
  currentUrl = out.currentUrl;

  if (res.status === 200 && res.body && res.body.includes('login') && res.body.includes('username')) {
    const formAction = extractFormAction(res.body);
    if (formAction) {
      const postUrl = resolveUrl(currentUrl, formAction);
      res = http.post(postUrl, { username: USERNAME, password: PASSWORD }, params);
      out = followRedirects(res, postUrl, params, MAX_REDIRECTS);
      res = out.res;
      currentUrl = out.currentUrl;
    }
  }

  const maybePosted = maybeHandleSamlPostBinding(res, currentUrl, params);
  if (maybePosted) {
    res = maybePosted;
    out = followRedirects(res, currentUrl, params, MAX_REDIRECTS);
    res = out.res;
    currentUrl = out.currentUrl;
  }

  return {
    keycloakCookies: jar.cookiesForURL(KEYCLOAK_URL),
    appCookies: jar.cookiesForURL(BASE_URL),
  };
}

export default function (data) {
  const scenario = Math.random();
  
  if (scenario < 0.3) {
    doColdLogin();
  } else if (scenario < 0.7) {
    doWarmIdpLogin(data || {});
  } else {
    doSessionReuse(data || {});
  }
  
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

