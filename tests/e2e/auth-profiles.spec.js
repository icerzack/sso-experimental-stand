const fs = require('node:fs/promises');
const path = require('node:path');
const { test, expect } = require('@playwright/test');

const metricsPath = path.join(process.cwd(), 'results', 'playwright', 'profile-metrics.json');
const summaryPath = path.join(process.cwd(), 'results', 'playwright', 'profile-metrics-summary.json');
const profileMetrics = [];

const humanMode = process.env.HUMAN_MODE === '1';
const networkProfile = process.env.NETWORK_PROFILE || 'slow4g';

const THINK_MIN_MS = parseInt(process.env.HUMAN_THINK_MIN_MS || '250', 10);
const THINK_MAX_MS = parseInt(process.env.HUMAN_THINK_MAX_MS || '1200', 10);
const TYPE_MIN_MS = parseInt(process.env.HUMAN_TYPING_MIN_MS || '60', 10);
const TYPE_MAX_MS = parseInt(process.env.HUMAN_TYPING_MAX_MS || '180', 10);
const vaultwardenUrl = process.env.VAULTWARDEN_URL || 'https://vaultwarden.localhost';
const vaultwardenEmail = process.env.VAULTWARDEN_EMAIL || 'testuser1@example.com';
const vaultwardenMasterPassword = process.env.VAULTWARDEN_MASTER_PASSWORD || 'password123';
const vaultwardenItemName = process.env.VAULTWARDEN_ITEM_NAME || 'app.localhost';
const allowVaultwardenFallback = process.env.VAULTWARDEN_FALLBACK_CREDENTIALS !== '0';
const webAuthnAppBaseUrl = process.env.WEBAUTHN_APP_BASE_URL || 'http://localhost:8081';
const vaultwardenUsernameSelector = process.env.VAULTWARDEN_USERNAME_SELECTOR || [
  'input[name="login.username"]',
  'input[formcontrolname="username"]',
  'input[aria-label="Username"]',
  'input[placeholder="Username"]',
].join(', ');
const vaultwardenPasswordSelector = process.env.VAULTWARDEN_PASSWORD_SELECTOR || [
  'input[name="login.password"]',
  'input[formcontrolname="password"]',
  'input[aria-label="Password"]',
  'input[placeholder="Password"]',
].join(', ');

const networkProfiles = {
  wifi: {
    offline: false,
    latency: 20,
    downloadThroughput: (30 * 1024 * 1024) / 8,
    uploadThroughput: (10 * 1024 * 1024) / 8,
  },
  fast4g: {
    offline: false,
    latency: 85,
    downloadThroughput: (9 * 1024 * 1024) / 8,
    uploadThroughput: (3 * 1024 * 1024) / 8,
  },
  slow4g: {
    offline: false,
    latency: 170,
    downloadThroughput: (1.6 * 1024 * 1024) / 8,
    uploadThroughput: (750 * 1024) / 8,
  },
  fast3g: {
    offline: false,
    latency: 150,
    downloadThroughput: (1.6 * 1024 * 1024) / 8,
    uploadThroughput: (750 * 1024) / 8,
  },
  slow3g: {
    offline: false,
    latency: 400,
    downloadThroughput: (500 * 1024) / 8,
    uploadThroughput: (500 * 1024) / 8,
  },
};

function randInt(min, max) {
  return Math.floor(min + Math.random() * (max - min + 1));
}

async function think(page, min = THINK_MIN_MS, max = THINK_MAX_MS) {
  if (!humanMode) {
    return;
  }
  await page.waitForTimeout(randInt(min, max));
}

async function typeHuman(locator, text) {
  const currentValue = await locator.inputValue();
  if (currentValue === text) {
    return;
  }

  if (!humanMode) {
    await locator.fill(text);
    return;
  }

  await locator.click();
  await locator.fill('');
  await locator.pressSequentially(text, { delay: randInt(TYPE_MIN_MS, TYPE_MAX_MS) });
}

async function applyNetworkProfile(context, page) {
  if (!humanMode) {
    return null;
  }
  const profile = networkProfiles[networkProfile];
  if (!profile) {
    throw new Error(`Unsupported NETWORK_PROFILE=${networkProfile}`);
  }
  const cdp = await context.newCDPSession(page);
  await cdp.send('Network.enable');
  await cdp.send('Network.emulateNetworkConditions', profile);
  return cdp;
}

function percentile(sortedNumbers, p) {
  if (sortedNumbers.length === 0) {
    return null;
  }
  const idx = Math.ceil((p / 100) * sortedNumbers.length) - 1;
  return sortedNumbers[Math.max(0, Math.min(idx, sortedNumbers.length - 1))];
}

function summarizeMetrics(metrics) {
  const byProfile = new Map();
  for (const entry of metrics) {
    if (!byProfile.has(entry.profile)) {
      byProfile.set(entry.profile, []);
    }
    byProfile.get(entry.profile).push(entry);
  }

  const profiles = [];
  for (const [profile, entries] of byProfile.entries()) {
    const durations = entries.map((e) => e.durationMs).sort((a, b) => a - b);
    const redirects = entries.map((e) => e.redirectCount);
    const steps = entries.map((e) => e.stepCount);
    const successCount = entries.filter((e) => e.status === 'success').length;

    profiles.push({
      profile,
      runs: entries.length,
      successRate: Number((successCount / entries.length).toFixed(4)),
      meanDurationMs: Number((durations.reduce((acc, v) => acc + v, 0) / durations.length).toFixed(2)),
      medianDurationMs: percentile(durations, 50),
      p95DurationMs: percentile(durations, 95),
      meanRedirectCount: Number((redirects.reduce((acc, v) => acc + v, 0) / redirects.length).toFixed(2)),
      meanStepCount: Number((steps.reduce((acc, v) => acc + v, 0) / steps.length).toFixed(2)),
    });
  }

  return {
    mode: humanMode ? 'human-like' : 'machine-baseline',
    networkProfile: humanMode ? networkProfile : 'none',
    generatedAt: new Date().toISOString(),
    totalRuns: metrics.length,
    profiles: profiles.sort((a, b) => a.profile.localeCompare(b.profile)),
  };
}

test.afterAll(async () => {
  await fs.mkdir(path.dirname(metricsPath), { recursive: true });
  await fs.writeFile(metricsPath, `${JSON.stringify(profileMetrics, null, 2)}\n`);
  await fs.writeFile(summaryPath, `${JSON.stringify(summarizeMetrics(profileMetrics), null, 2)}\n`);
});

async function measureLogin(page, profile, loginAction, testInfo) {
  let stepCount = 0;
  let redirectCount = 0;
  const startedAt = Date.now();

  const responseHandler = (response) => {
    const status = response.status();
    if (status >= 300 && status < 400) {
      redirectCount += 1;
    }
  };
  page.on('response', responseHandler);

  const step = async (action) => {
    stepCount += 1;
    await action();
  };

  try {
    await think(page, 150, 500);
    await step(() => page.goto('/'));
    await think(page);
    await loginAction(step);
    await expect(page.locator('body')).toContainText(profile);
    profileMetrics.push({
      profile,
      durationMs: Date.now() - startedAt,
      redirectCount,
      stepCount,
      status: 'success',
      runIndex: testInfo.repeatEachIndex,
      testTitle: testInfo.title,
      mode: humanMode ? 'human-like' : 'machine-baseline',
      networkProfile: humanMode ? networkProfile : 'none',
    });
  } catch (error) {
    profileMetrics.push({
      profile,
      durationMs: Date.now() - startedAt,
      redirectCount,
      stepCount,
      status: 'error',
      error: error.message,
      runIndex: testInfo.repeatEachIndex,
      testTitle: testInfo.title,
      mode: humanMode ? 'human-like' : 'machine-baseline',
      networkProfile: humanMode ? networkProfile : 'none',
    });
    throw error;
  } finally {
    page.off('response', responseHandler);
  }
}

async function fillUsernameIfVisible(page, username) {
  const usernameInput = page.locator('input[name="username"]');
  if (await usernameInput.first().isVisible()) {
    await think(page);
    await typeHuman(usernameInput.first(), username);
    await think(page, 100, 350);
    await page.locator('input[type="submit"], button[type="submit"]').first().click();
    await page.waitForLoadState('domcontentloaded');
  }
}

async function submitFirstVisibleForm(page) {
  const submit = page.locator('input[type="submit"], button[type="submit"]').first();
  if (await submit.isVisible()) {
    await think(page, 100, 300);
    await submit.click();
    await page.waitForLoadState('domcontentloaded');
  }
}

async function firstVisibleLocator(page, selector, description) {
  const candidates = page.locator(selector);
  const count = await candidates.count();
  for (let i = 0; i < count; i += 1) {
    const candidate = candidates.nth(i);
    if (await candidate.isVisible()) {
      return candidate;
    }
  }
  throw new Error(`Could not find visible ${description} using selector: ${selector}`);
}

async function clickFirstVisible(page, locators, description) {
  for (const locator of locators) {
    if (await locator.first().isVisible()) {
      await locator.first().click();
      await page.waitForLoadState('domcontentloaded').catch(() => {});
      return;
    }
  }
  throw new Error(`Could not find visible ${description}`);
}

async function unlockVaultwarden(vaultPage) {
  await vaultPage.goto(vaultwardenUrl);
  await think(vaultPage);

  const emailInput = vaultPage.locator('input[type="email"], input[name="email"], input[autocomplete="username"]').first();
  if (await emailInput.isVisible()) {
    await typeHuman(emailInput, vaultwardenEmail);
    await think(vaultPage, 100, 350);
    await clickFirstVisible(
      vaultPage,
      [
        vaultPage.getByRole('button', { name: /continue|next|далее|продолжить/i }),
        vaultPage.locator('button[type="submit"], input[type="submit"]'),
      ],
      'Vaultwarden email submit button',
    );
  }

  const passwordInput = vaultPage.locator('input[type="password"], input[name="masterPassword"]').first();
  if (await passwordInput.isVisible()) {
    await typeHuman(passwordInput, vaultwardenMasterPassword);
    await think(vaultPage, 100, 350);
    await clickFirstVisible(
      vaultPage,
      [
        vaultPage.getByRole('button', { name: /log in|unlock|разблокировать|войти/i }),
        vaultPage.locator('button[type="submit"], input[type="submit"]'),
      ],
      'Vaultwarden password submit button',
    );
  }
}

async function retrieveVaultwardenCredentials(context) {
  if (allowVaultwardenFallback) {
    return {
      username: process.env.LOCAL_LOGIN_USERNAME || 'testuser1',
      password: process.env.LOCAL_LOGIN_PASSWORD || 'password123',
    };
  }

  const vaultPage = await context.newPage();
  const networkCdp = await applyNetworkProfile(context, vaultPage);
  try {
    await unlockVaultwarden(vaultPage);
    await expect(vaultPage.locator('body')).toContainText(vaultwardenItemName, { timeout: 10_000 });

    const searchInput = vaultPage.locator('input[type="search"], input[placeholder*="Search"], input[aria-label*="Search"]').first();
    if (await searchInput.isVisible()) {
      await typeHuman(searchInput, vaultwardenItemName);
      await think(vaultPage, 150, 500);
    }

    await vaultPage.getByText(vaultwardenItemName, { exact: true }).first().click();
    await think(vaultPage, 200, 600);

    const editButton = vaultPage.getByRole('button', { name: /edit|редактировать/i });
    if (await editButton.first().isVisible()) {
      await editButton.first().click();
      await vaultPage.waitForLoadState('domcontentloaded').catch(() => {});
    }

    const usernameInput = await firstVisibleLocator(vaultPage, vaultwardenUsernameSelector, 'Vaultwarden username field');
    const passwordInput = await firstVisibleLocator(vaultPage, vaultwardenPasswordSelector, 'Vaultwarden password field');
    const username = await usernameInput.inputValue();
    const password = await passwordInput.inputValue();
    if (!username || !password) {
      throw new Error(`Vaultwarden item "${vaultwardenItemName}" has empty username or password fields`);
    }
    return { username, password };
  } finally {
    if (networkCdp) {
      await networkCdp.detach();
    }
    await vaultPage.close();
  }
}

test('profile A authenticates through Keycloak password flow', async ({ page, context }, testInfo) => {
  const networkCdp = await applyNetworkProfile(context, page);
  try {
    await measureLogin(
      page,
      'profile-a',
      async (step) => {
        await step(() => page.locator('[data-profile="profile-a"] a').click());
        await step(() => typeHuman(page.locator('input[name="username"]'), process.env.PROFILE_A_USERNAME || 'testuser1'));
        await step(() => typeHuman(page.locator('input[name="password"]'), process.env.PROFILE_A_PASSWORD || 'password123'));
        await step(async () => {
          await think(page, 120, 400);
          await page.locator('input[type="submit"], button[type="submit"]').first().click();
        });
        await step(() => expect(page).toHaveURL(/\/protected$/));
      },
      testInfo,
    );
  } finally {
    if (networkCdp) {
      await networkCdp.detach();
    }
  }
});

test('profile B registers and authenticates through direct WebAuthn passkey flow', async ({ page, context }, testInfo) => {
  const networkCdp = await applyNetworkProfile(context, page);
  const webAuthnCdp = await context.newCDPSession(page);
  await webAuthnCdp.send('WebAuthn.enable');
  await webAuthnCdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });

  await page.goto(webAuthnAppBaseUrl);
  await think(page);
  await page.locator('[data-profile="profile-b"] a[href^="/login/"]').click();
  await page.locator('#register-passkey').click();
  await expect(page).toHaveURL(/\/protected$/);
  await think(page, 150, 450);
  await page.locator('a[href="/logout"]').click();
  await expect(page).toHaveURL(/\/$/);

  try {
    await measureLogin(
      page,
      'profile-b',
      async (step) => {
        await step(() => page.goto(webAuthnAppBaseUrl));
        await step(() => page.locator('[data-profile="profile-b"] a[href^="/login/"]').click());
        await step(() => page.locator('#login-passkey').click());
        await step(() => expect(page).toHaveURL(/\/protected$/));
      },
      testInfo,
    );
  } finally {
    await webAuthnCdp.detach();
    if (networkCdp) {
      await networkCdp.detach();
    }
  }
});

test('profile C authenticates through local form for Vaultwarden-filled credentials', async ({ page, context }, testInfo) => {
  const networkCdp = await applyNetworkProfile(context, page);
  try {
    await measureLogin(
      page,
      'profile-c',
      async (step) => {
        let credentials;
        await step(async () => {
          credentials = await retrieveVaultwardenCredentials(context);
        });
        await step(() => page.locator('[data-profile="profile-c"] a').click());
        await step(() => typeHuman(page.locator('input[name="username"]'), credentials.username));
        await step(() => typeHuman(page.locator('input[name="password"]'), credentials.password));
        await step(async () => {
          await think(page, 120, 400);
          await page.locator('button[type="submit"]').click();
        });
        await step(() => expect(page).toHaveURL(/\/protected$/));
      },
      testInfo,
    );
  } finally {
    if (networkCdp) {
      await networkCdp.detach();
    }
  }
});
