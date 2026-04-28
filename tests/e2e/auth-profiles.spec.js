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
const PROFILE_A_USER = process.env.PROFILE_A_USER || 'testuser1';
const PROFILE_A_PASS = process.env.PROFILE_A_PASS || 'password123';
const PROFILE_B_URL  = process.env.PROFILE_B_URL  || 'https://app-b-h.local';
const PROFILE_C_URL  = process.env.PROFILE_C_URL  || 'https://app-c-h.local';
const PROFILE_C_EMAIL = process.env.PROFILE_C_EMAIL || 'testuser@example.com';
const PROFILE_C_PASS  = process.env.PROFILE_C_PASS  || 'password123';

const metricsPath = path.join(process.cwd(), 'results', 'playwright', 'metrics.json');
const metrics = [];

test.afterAll(async () => {
  await fs.mkdir(path.dirname(metricsPath), { recursive: true });
  await fs.writeFile(metricsPath, JSON.stringify(metrics, null, 2) + '\n');
});

function record(profile, durationMs, status, note = '') {
  metrics.push({ profile, durationMs, status, note, ts: new Date().toISOString() });
}

// ── Profile A: OIDC / Keycloak password flow ─────────────────────────────────
test('Profile A — OIDC login via Keycloak redirects to /protected', async ({ page }) => {
  const t0 = Date.now();
  try {
    await page.goto(PROFILE_A_URL + '/login');

    // Keycloak login page
    await page.locator('input[name="username"]').fill(PROFILE_A_USER);
    await page.locator('input[name="password"]').fill(PROFILE_A_PASS);
    await page.locator('input[type="submit"], button[type="submit"]').first().click();

    // Should land on /protected
    await expect(page).toHaveURL(/\/protected/, { timeout: 15_000 });
    await expect(page.locator('body')).toContainText(PROFILE_A_USER);

    record('profile-a', Date.now() - t0, 'success');
  } catch (err) {
    record('profile-a', Date.now() - t0, 'error', err.message);
    throw err;
  }
});

test('Profile A — /protected redirects unauthenticated visitor to login', async ({ page }) => {
  await page.goto(PROFILE_A_URL + '/protected');
  // Should be redirected away from /protected
  await expect(page).not.toHaveURL(/\/protected/, { timeout: 10_000 });
});

// ── Profile B: WebAuthn / FIDO2 passkey flow ─────────────────────────────────
test('Profile B — WebAuthn registration then login reaches /protected', async ({ page, context }) => {
  const t0 = Date.now();

  // Virtual authenticator (Chromium CDP)
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
    // ── Register ──────────────────────────────────────────
    await page.goto(PROFILE_B_URL + '/');
    await page.locator('#register-passkey, button:has-text("Register"), a:has-text("Register")').first().click();
    await expect(page).toHaveURL(/\/protected/, { timeout: 15_000 });

    // ── Logout ────────────────────────────────────────────
    await page.locator('a[href="/logout"], button:has-text("Logout")').first().click();
    await expect(page).not.toHaveURL(/\/protected/, { timeout: 8_000 });

    // ── Login with passkey ────────────────────────────────
    await page.goto(PROFILE_B_URL + '/');
    await page.locator('#login-passkey, button:has-text("Login"), a:has-text("Login")').first().click();
    await expect(page).toHaveURL(/\/protected/, { timeout: 15_000 });

    record('profile-b', Date.now() - t0, 'success');
  } catch (err) {
    record('profile-b', Date.now() - t0, 'error', err.message);
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

// ── Profile C: Go app + Vaultwarden backend ─────────────────────────────────
test('Profile C — login flow reaches /protected', async ({ page }) => {
  const t0 = Date.now();
  try {
    await page.goto(PROFILE_C_URL + '/');
    await page.locator('input[name="email"]').fill(PROFILE_C_EMAIL);
    await page.locator('input[name="password"]').fill(PROFILE_C_PASS);
    await page.locator('button[type="submit"], button:has-text("Login")').first().click();

    await expect(page).toHaveURL(/\/protected/, { timeout: 15_000 });
    await expect(page.locator('body')).toContainText(PROFILE_C_EMAIL);

    record('profile-c-login', Date.now() - t0, 'success');
  } catch (err) {
    record('profile-c-login', Date.now() - t0, 'error', err.message);
    throw err;
  }
});

test('Profile C — wrong password does not reach /protected', async ({ page }) => {
  const t0 = Date.now();
  try {
    await page.goto(PROFILE_C_URL + '/');
    await page.locator('input[name="email"]').fill(PROFILE_C_EMAIL);
    await page.locator('input[name="password"]').fill(PROFILE_C_PASS + '-wrong');
    await page.locator('button[type="submit"], button:has-text("Login")').first().click();

    await expect(page).not.toHaveURL(/\/protected/, { timeout: 8_000 });

    record('profile-c-reject', Date.now() - t0, 'success');
  } catch (err) {
    record('profile-c-reject', Date.now() - t0, 'error', err.message);
    throw err;
  }
});
