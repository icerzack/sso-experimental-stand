/**
 * E2E smoke tests for the SSO Experimental Stand.
 *
 * Each test targets one hardened profile app endpoint.
 *
 * Environment variables:
 *   PROFILE_A_URL   base URL for Profile A app     (default: https://app-a-h.local)
 *   PROFILE_A_USER  Keycloak username               (default: testuser1)
 *   PROFILE_A_PASS  Keycloak password               (default: password123)
 *   PROFILE_B_URL   base URL for Profile B app      (default: https://app-b-h.local)
 *   PROFILE_C_URL   base URL for Profile C app      (default: https://app-c-h.local)
 *   PROFILE_C_EMAIL Profile C account e-mail        (default: testuser@example.com)
 *   PROFILE_C_PASS  Profile C password              (default: password123)
 */

const { test, expect } = require('@playwright/test');
const fs = require('node:fs/promises');
const path = require('node:path');

const PROFILE_A_URL  = process.env.PROFILE_A_URL  || 'https://app-a-h.local';
const PROFILE_A_USER = process.env.PROFILE_A_USER || 'testuser';
const PROFILE_A_PASS = process.env.PROFILE_A_PASS || 'testpass123';
const PROFILE_B_URL  = process.env.PROFILE_B_URL  || 'https://app-b-h.local';
const PROFILE_C_URL  = process.env.PROFILE_C_URL  || 'https://app-c-h.local';
const PROFILE_C_EMAIL = process.env.PROFILE_C_EMAIL || 'testuser@example.com';
const PROFILE_C_PASS  = process.env.PROFILE_C_PASS  || 'password123';

const metricsPath = path.join(process.cwd(), 'results', 'playwright', 'profile-metrics.json');
const metrics = [];

test.afterAll(async () => {
  await fs.mkdir(path.dirname(metricsPath), { recursive: true });
  let existing = [];
  try {
    existing = JSON.parse(await fs.readFile(metricsPath, 'utf8'));
    if (!Array.isArray(existing)) {
      existing = [];
    }
  } catch (_) {
    existing = [];
  }

  const merged = [...existing];
  for (const item of metrics) {
    const idx = merged.findIndex((entry) => entry.profile === item.profile && entry.runIndex === item.runIndex);
    if (idx >= 0) {
      merged[idx] = item;
    } else {
      merged.push(item);
    }
  }

  await fs.writeFile(metricsPath, JSON.stringify(merged, null, 2) + '\n');
});

function beginMetricsCollection(page) {
  let redirectCount = 0;
  let stepCount = 0;

  const onResponse = (response) => {
    stepCount += 1;
    const status = response.status();
    if (status >= 300 && status < 400) {
      redirectCount += 1;
    }
  };

  page.on('response', onResponse);
  return {
    finish() {
      page.off('response', onResponse);
      return { redirectCount, stepCount };
    },
  };
}

function record(profile, durationMs, status, testTitle, runIndex, networkProfile, redirectCount, stepCount) {
  const item = {
    profile,
    durationMs,
    redirectCount,
    stepCount,
    status,
    runIndex,
    testTitle,
    mode: process.env.HUMAN_MODE ? 'human' : 'machine-baseline',
    networkProfile,
  };

  const existingIndex = metrics.findIndex((entry) => entry.profile === profile && entry.runIndex === runIndex);
  if (existingIndex >= 0) {
    metrics[existingIndex] = item;
    return;
  }
  metrics.push(item);
}

async function waitForKeycloakLogin(page) {
  await page.waitForURL((url) => {
    const s = url.toString();
    return s.includes('keycloak.local') || /\/protected(?:$|[/?#])/.test(s);
  }, { timeout: 60_000 });

  if (/\/protected(?:$|[/?#])/.test(page.url())) {
    return false;
  }

  await page.waitForLoadState('domcontentloaded');
  await page.locator('#kc-login, #kc-form-login, form#kc-form-login, input[name="username"]').first().waitFor({
    state: 'visible',
    timeout: 30_000,
  });
  return true;
}

async function fillIfVisible(locator, value) {
  if (await locator.count()) {
    const first = locator.first();
    if (await first.isVisible()) {
      await first.fill(value);
      return true;
    }
  }
  return false;
}

async function completeKeycloakLogin(page) {
  await fillIfVisible(
    page.locator('input[name="username"], input#username, input[name="email"], input[type="email"]'),
    PROFILE_A_USER,
  );
  await fillIfVisible(page.locator('input[name="password"], input#password'), PROFILE_A_PASS);

  const submit = page.locator('#kc-login, input[type="submit"], button[type="submit"]');
  await submit.first().click({ timeout: 20_000 });
  await page.waitForURL((url) => /\/protected(?:$|[/?#])/.test(url.toString()), { timeout: 90_000 });
}

async function runWebAuthnAction(page, triggerSelector, finishPath, actionLabel, baseUrl) {
  const finishResponsePromise = page.waitForResponse(
    (response) => response.url().includes(finishPath),
    { timeout: 30_000 },
  );

  await page.locator(triggerSelector).first().click({ timeout: 20_000 });

  const finishResponse = await finishResponsePromise;
  if (!finishResponse.ok()) {
    const body = await finishResponse.text().catch(() => '');
    throw new Error(`${actionLabel} finish endpoint failed: HTTP ${finishResponse.status()} ${body}`.trim());
  }

  await page.waitForURL(/\/protected/, { timeout: 15_000 });
}

test('Profile A — OIDC login via Keycloak redirects to /protected', async ({ page }) => {
  test.setTimeout(180_000);
  const t0 = Date.now();
  const collector = beginMetricsCollection(page);
  const runIndex = Number(process.env.PW_RUN_INDEX || 0);
  const networkProfile = process.env.NETWORK_PROFILE || 'none';
  const testTitle = 'profile A authenticates through Keycloak password flow';
  try {
    await page.goto(PROFILE_A_URL + '/');
    await page.locator('a[href="/login"], a:has-text("Login with Keycloak")').first().click();
    const needsCredentials = await waitForKeycloakLogin(page);
    if (needsCredentials) {
      await completeKeycloakLogin(page);
    }

    await expect(page).toHaveURL(/\/protected/, { timeout: 60_000 });
    await expect(page.locator('body')).toContainText(PROFILE_A_USER);

    const { redirectCount, stepCount } = collector.finish();
    record('profile-a', Date.now() - t0, 'success', testTitle, runIndex, networkProfile, redirectCount, stepCount);
  } catch (err) {
    const { redirectCount, stepCount } = collector.finish();
    record('profile-a', Date.now() - t0, 'failed', testTitle, runIndex, networkProfile, redirectCount, stepCount);
    throw err;
  }
});

test('Profile A — /protected redirects unauthenticated visitor to login', async ({ page }) => {
  await page.goto(PROFILE_A_URL + '/protected');
  await expect(page).not.toHaveURL(/\/protected/, { timeout: 10_000 });
});

test('Profile B — WebAuthn registration then login reaches /protected', async ({ page, context }) => {
  test.setTimeout(180_000);
  const t0 = Date.now();
  const collector = beginMetricsCollection(page);
  const runIndex = Number(process.env.PW_RUN_INDEX || 0);
  const networkProfile = process.env.NETWORK_PROFILE || 'none';
  const testTitle = 'profile B registers and authenticates through direct WebAuthn passkey flow';

  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });

  try {
    await page.goto(PROFILE_B_URL + '/');
    await runWebAuthnAction(
      page,
      '#reg, #register-passkey, button:has-text("Register"), a:has-text("Register")',
      '/webauthn/register/finish',
      'Passkey registration',
      PROFILE_B_URL,
    );

    await page.locator('a[href="/logout"], button:has-text("Logout")').first().click();
    await expect(page).not.toHaveURL(/\/protected/, { timeout: 8_000 });

    await page.goto(PROFILE_B_URL + '/');
    await runWebAuthnAction(
      page,
      '#login, #login-passkey, button:has-text("Login"), a:has-text("Login")',
      '/webauthn/login/finish',
      'Passkey login',
      PROFILE_B_URL,
    );

    const { redirectCount, stepCount } = collector.finish();
    record('profile-b', Date.now() - t0, 'success', testTitle, runIndex, networkProfile, redirectCount, stepCount);
  } catch (err) {
    const { redirectCount, stepCount } = collector.finish();
    record('profile-b', Date.now() - t0, 'failed', testTitle, runIndex, networkProfile, redirectCount, stepCount);
    throw err;
  } finally {
    await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
    await cdp.detach();
  }
});

test('Profile B — /protected redirects unauthenticated visitor', async ({ page }) => {
  await page.goto(PROFILE_B_URL + '/protected');
  await expect(page).not.toHaveURL(/\/protected/, { timeout: 10_000 });
});

test('Profile C — login flow reaches /protected', async ({ page }) => {
  const t0 = Date.now();
  const collector = beginMetricsCollection(page);
  const runIndex = Number(process.env.PW_RUN_INDEX || 0);
  const networkProfile = process.env.NETWORK_PROFILE || 'none';
  const testTitle = 'profile C authenticates through local form for Vaultwarden-filled credentials';
  try {
    await page.goto(PROFILE_C_URL + '/');
    await page.locator('input[name="email"]').fill(PROFILE_C_EMAIL);
    await page.locator('input[name="password"]').fill(PROFILE_C_PASS);
    await page.locator('button[type="submit"], button:has-text("Login")').first().click();

    await expect(page).toHaveURL(/\/protected/, { timeout: 15_000 });
    await expect(page.locator('body')).toContainText(PROFILE_C_EMAIL);

    const { redirectCount, stepCount } = collector.finish();
    record('profile-c', Date.now() - t0, 'success', testTitle, runIndex, networkProfile, redirectCount, stepCount);
  } catch (err) {
    const { redirectCount, stepCount } = collector.finish();
    record('profile-c', Date.now() - t0, 'failed', testTitle, runIndex, networkProfile, redirectCount, stepCount);
    throw err;
  }
});

test('Profile C — wrong password does not reach /protected', async ({ page }) => {
  await page.goto(PROFILE_C_URL + '/');
  await page.locator('input[name="email"]').fill(PROFILE_C_EMAIL);
  await page.locator('input[name="password"]').fill(PROFILE_C_PASS + '-wrong');
  await page.locator('button[type="submit"], button:has-text("Login")').first().click();
  await expect(page).not.toHaveURL(/\/protected/, { timeout: 8_000 });
});
