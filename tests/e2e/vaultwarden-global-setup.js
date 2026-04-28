const { chromium, expect } = require('@playwright/test');
const fs = require('node:fs/promises');
const path = require('node:path');

const vaultwardenUrl = process.env.VAULTWARDEN_URL || 'https://vaultwarden.localhost';
const vaultwardenEmail = process.env.VAULTWARDEN_EMAIL || 'testuser1@example.com';
const vaultwardenMasterPassword = process.env.VAULTWARDEN_MASTER_PASSWORD || 'password123';
const vaultwardenItemName = process.env.VAULTWARDEN_ITEM_NAME || 'app.localhost';
const appUsername = process.env.LOCAL_LOGIN_USERNAME || 'testuser1';
const appPassword = process.env.LOCAL_LOGIN_PASSWORD || 'password123';
const diagnosticsDir = path.join(process.cwd(), 'results', 'playwright', 'vaultwarden-setup');
const allowVaultwardenRegister = process.env.VAULTWARDEN_ALLOW_REGISTER === '1';
const allowVaultwardenFallback = process.env.VAULTWARDEN_FALLBACK_CREDENTIALS !== '0';

const usernameSelector = process.env.VAULTWARDEN_USERNAME_SELECTOR || [
  'input[name="login.username"]',
  'input[formcontrolname="username"]',
  'input[aria-label="Username"]',
  'input[placeholder="Username"]',
].join(', ');

const passwordSelector = process.env.VAULTWARDEN_PASSWORD_SELECTOR || [
  'input[name="login.password"]',
  'input[formcontrolname="password"]',
  'input[aria-label="Password"]',
  'input[placeholder="Password"]',
].join(', ');

async function isVisible(locator, timeout = 1500) {
  try {
    await locator.first().waitFor({ state: 'visible', timeout });
    return true;
  } catch {
    return false;
  }
}

async function clickFirstVisible(page, locators, description) {
  for (const locator of locators) {
    const count = await locator.count();
    for (let i = 0; i < count; i += 1) {
      const candidate = locator.nth(i);
      if (await isVisible(candidate)) {
        await candidate.click();
        await page.waitForLoadState('domcontentloaded').catch(() => {});
        return;
      }
    }
  }
  await writeDiagnostics(page, `missing-${description.toLowerCase().replaceAll(' ', '-')}`);
  throw new Error(`Could not find visible ${description}`);
}

async function fillFirstVisible(page, locators, value, description) {
  for (const locator of locators) {
    const count = await locator.count();
    for (let i = 0; i < count; i += 1) {
      const candidate = locator.nth(i);
      if (await isVisible(candidate)) {
        await candidate.fill(value);
        return;
      }
    }
  }
  await writeDiagnostics(page, `missing-${description.toLowerCase().replaceAll(' ', '-')}`);
  throw new Error(`Could not find visible ${description}`);
}

async function fillVisibleAt(page, locators, visibleIndex, value, description) {
  let seen = 0;
  for (const locator of locators) {
    const count = await locator.count();
    for (let i = 0; i < count; i += 1) {
      const candidate = locator.nth(i);
      if (await isVisible(candidate)) {
        if (seen === visibleIndex) {
          await candidate.fill(value);
          return;
        }
        seen += 1;
      }
    }
  }
  await writeDiagnostics(page, `missing-${description.toLowerCase().replaceAll(' ', '-')}`);
  throw new Error(`Could not find visible ${description}`);
}

async function hasVisible(page, locators) {
  for (const locator of locators) {
    const count = await locator.count();
    for (let i = 0; i < count; i += 1) {
      if (await isVisible(locator.nth(i), 300)) {
        return true;
      }
    }
  }
  return false;
}

async function writeDiagnostics(page, name) {
  await fs.mkdir(diagnosticsDir, { recursive: true });
  await page.screenshot({ path: path.join(diagnosticsDir, `${name}.png`), fullPage: true }).catch(() => {});
  await fs.writeFile(path.join(diagnosticsDir, `${name}.html`), await page.content()).catch(() => {});
  const controls = await page.locator('input, button, a').evaluateAll((elements) =>
    elements.map((el) => ({
      tag: el.tagName.toLowerCase(),
      type: el.getAttribute('type'),
      name: el.getAttribute('name'),
      formcontrolname: el.getAttribute('formcontrolname'),
      placeholder: el.getAttribute('placeholder'),
      ariaLabel: el.getAttribute('aria-label'),
      text: el.textContent?.trim(),
      visible: !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length),
    })),
  ).catch((error) => [{ error: error.message }]);
  const toasts = await page.locator('#toast-container [role="alert"], #toast-container .toast-message, #toast-container .toast-title, #toast-container .toast')
    .allTextContents()
    .catch(() => []);
  await fs.writeFile(path.join(diagnosticsDir, `${name}.controls.json`), `${JSON.stringify(controls, null, 2)}\n`).catch(() => {});
  await fs.writeFile(path.join(diagnosticsDir, `${name}.toasts.json`), `${JSON.stringify(toasts, null, 2)}\n`).catch(() => {});
}

async function hasInsecureURLToast(page) {
  const messages = await page.locator('#toast-container [role="alert"], #toast-container .toast-message, #toast-container .toast-title, #toast-container .toast')
    .allTextContents()
    .catch(() => []);
  return messages.some((message) => /insecure url not allowed|all urls must use https/i.test(String(message)));
}

async function waitForAnyVisible(page, locators, timeout = 10_000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (await hasVisible(page, locators)) {
      return true;
    }
    await page.waitForTimeout(250);
  }
  return false;
}

async function isAuthScreen(page) {
  const emailContinueButton = page.getByRole('button', { name: /continue/i });
  const masterLoginButton = page.getByRole('button', { name: /log in with master password/i });
  const createAccountLink = page.getByRole('link', { name: /create account/i });
  return (await isVisible(emailContinueButton, 400)) || (await isVisible(masterLoginButton, 400)) || (await isVisible(createAccountLink, 400));
}

async function isVaultReady(page) {
  const url = page.url();
  const looksLikeVaultPage = url.includes('/#/vault');
  const stillOnAuth = await isAuthScreen(page);
  return looksLikeVaultPage && !stillOnAuth;
}

async function submitMasterPassword(page) {
  const password = page.locator('input[type="password"], input[name="masterPassword"], input[formcontrolname="masterPassword"]');
  if (!(await isVisible(password, 2000))) {
    return false;
  }
  await password.first().click();
  await password.first().fill(vaultwardenMasterPassword);
  await expect(password.first()).toHaveValue(vaultwardenMasterPassword, { timeout: 5_000 });
  await password.first().dispatchEvent('input').catch(() => {});
  await password.first().dispatchEvent('change').catch(() => {});
  const submitCandidates = [
    page.getByRole('button', { name: /log in with master password|unlock|войти|разблокировать/i }),
    page.locator('button[type="submit"], input[type="submit"]'),
  ];
  await clickFirstVisible(page, submitCandidates, 'Vaultwarden password submit button').catch(() => {});
  await password.first().press('Enter').catch(() => {});
  await page.waitForLoadState('domcontentloaded').catch(() => {});
  await page.waitForLoadState('networkidle').catch(() => {});
  return true;
}

async function maybeRegisterAccount(page) {
  await page.goto(`${vaultwardenUrl}/#/register`);
  await page.waitForLoadState('domcontentloaded');

  const email = page.locator('input[type="email"], input[name="email"], input[formcontrolname="email"]');
  if (!(await isVisible(email))) {
    return;
  }

  await fillFirstVisible(
    page,
    [
      page.locator('input[name="name"], input[formcontrolname="name"], input[autocomplete="name"]'),
      page.locator('input[placeholder*="Name"], input[aria-label*="Name"]'),
    ],
    'SSO Test User',
    'Vaultwarden registration name field',
  );
  await email.first().fill(vaultwardenEmail);

  const registrationPasswordLocators = [
    page.locator('input[name="masterPassword"], input[formcontrolname="masterPassword"]'),
    page.locator('input[type="password"]'),
  ];
  if (!(await hasVisible(page, registrationPasswordLocators))) {
    await clickFirstVisible(
      page,
      [
        page.getByRole('button', { name: /continue|next|далее|продолжить/i }),
        page.locator('button[type="submit"], input[type="submit"]'),
      ],
      'Vaultwarden registration continue button',
    ).catch(() => {});
    await page.waitForLoadState('networkidle').catch(() => {});
    await waitForAnyVisible(page, registrationPasswordLocators, 10_000);
  }

  if (!(await hasVisible(page, registrationPasswordLocators))) {
    await writeDiagnostics(page, 'vaultwarden-registration-password-step-not-visible');
    return;
  }

  await fillVisibleAt(
    page,
    registrationPasswordLocators,
    0,
    vaultwardenMasterPassword,
    'Vaultwarden registration master password field',
  );
  await fillVisibleAt(
    page,
    [
      page.locator('input[name="masterPasswordRetype"], input[formcontrolname="masterPasswordRetype"]'),
      page.locator('input[type="password"]'),
    ],
    1,
    vaultwardenMasterPassword,
    'Vaultwarden registration repeated master password field',
  );

  const hint = page.locator('input[name="masterPasswordHint"], input[formcontrolname="masterPasswordHint"]');
  if (await isVisible(hint, 500)) {
    await hint.first().fill('test stand');
  }

  const terms = page.locator('input[type="checkbox"]');
  const termsCount = await terms.count();
  for (let i = 0; i < termsCount; i += 1) {
    const checkbox = terms.nth(i);
    if ((await checkbox.isVisible()) && !(await checkbox.isChecked().catch(() => true))) {
      await checkbox.check().catch(() => {});
    }
  }

  await clickFirstVisible(
    page,
    [
      page.getByRole('button', { name: /create account|submit|создать|зарегистр/i }),
      page.locator('button[type="submit"], input[type="submit"]'),
    ],
    'Vaultwarden create account button',
  ).catch(() => {});
}

async function loginOrUnlock(page) {
  await page.context().clearCookies().catch(() => {});
  await page.goto(`${vaultwardenUrl}/#/login`);
  await page.waitForLoadState('domcontentloaded');
  await page.evaluate(() => {
    window.sessionStorage?.clear();
  }).catch(() => {});
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    const toastClose = page.getByRole('button', { name: /close/i });
    if (await isVisible(toastClose, 300)) {
      await toastClose.first().click().catch(() => {});
    }

    const email = page.locator('input[type="email"], input[name="email"], input[autocomplete="username"]');
    if (await isVisible(email, 500)) {
      await email.first().fill(vaultwardenEmail);
      await clickFirstVisible(
        page,
        [
          page.getByRole('button', { name: /continue|next|далее|продолжить/i }),
          page.locator('button[type="submit"], input[type="submit"]'),
        ],
        'Vaultwarden email submit button',
      ).catch(() => {});
      await waitForAnyVisible(
        page,
        [
          page.locator('input[formcontrolname="masterPassword"], input[name="masterPassword"], input[type="password"]'),
          page.getByRole('button', { name: /log in with master password|unlock|войти|разблокировать/i }),
        ],
        5_000,
      );
    }

    await submitMasterPassword(page);
    if (await isVaultReady(page)) {
      return;
    }

    if (attempt < 3) {
      const backButton = page.getByRole('button', { name: /back|назад/i });
      if (await isVisible(backButton, 500)) {
        await backButton.first().click().catch(() => {});
        await page.waitForLoadState('domcontentloaded').catch(() => {});
      } else {
        await page.goto(`${vaultwardenUrl}/#/login`);
        await page.waitForLoadState('domcontentloaded').catch(() => {});
      }
    }
  }

  await writeDiagnostics(page, 'login-or-unlock-not-completed');
  throw new Error(`Vaultwarden unlock did not complete (url=${page.url()}, authScreen=${await isAuthScreen(page)})`);
}

async function tryLoginOrUnlock(page) {
  try {
    await loginOrUnlock(page);
    return true;
  } catch {
    await writeDiagnostics(page, 'login-or-unlock-failed');
    return false;
  }
}

async function itemExists(page) {
  await page.goto(`${vaultwardenUrl}/#/vault?search=${encodeURIComponent(vaultwardenItemName)}`);
  await page.waitForLoadState('domcontentloaded');

  const search = page.locator('input[type="search"], input[placeholder*="Search"], input[aria-label*="Search"]');
  if (await isVisible(search, 1000)) {
    await search.first().fill(vaultwardenItemName);
  }

  return isVisible(page.getByText(vaultwardenItemName, { exact: true }), 2000);
}

async function unlockIfLocked(page) {
  const masterPassword = page.locator('input[formcontrolname="masterPassword"], input[name="masterPassword"], input[type="password"], input[type="text"][formcontrolname="masterPassword"]');
  const unlockButton = page.getByRole('button', { name: /log in with master password|unlock|войти|разблокировать/i });
  if (await isVisible(masterPassword, 1200) && await isVisible(unlockButton, 1200)) {
    await masterPassword.first().fill(vaultwardenMasterPassword);
    await unlockButton.first().click();
    await page.waitForLoadState('domcontentloaded').catch(() => {});
    await page.waitForLoadState('networkidle').catch(() => {});
  }
}

async function createLoginItem(page) {
  await page.goto(`${vaultwardenUrl}/#/vault/add`);
  await page.waitForLoadState('domcontentloaded');
  await page.waitForLoadState('networkidle').catch(() => {});
  await unlockIfLocked(page);

  const nameFields = [
    page.locator('input[name="name"], input[formcontrolname="name"]'),
    page.locator('input[placeholder="Name"], input[aria-label="Name"]'),
  ];
  if (!(await hasVisible(page, nameFields))) {
    await page.goto(`${vaultwardenUrl}/#/vault`);
    await page.waitForLoadState('domcontentloaded');
    await page.waitForLoadState('networkidle').catch(() => {});
    await unlockIfLocked(page);

    await clickFirstVisible(
      page,
      [
        page.getByRole('button', { name: /\+\s*new|\+\s*нов|new item|add item|new|add|создать|добавить|новый/i }),
        page.locator('button[title*="New"], button[title*="Add"], a[href*="add"], button[aria-label*="New"], button[aria-label*="Add"]'),
        page.locator('button:has(svg), button:has(i)'),
      ],
      'Vaultwarden new item button',
    );
    await page.waitForLoadState('domcontentloaded').catch(() => {});

    const loginOption = page.getByRole('menuitem', { name: /login|логин/i });
    if (await isVisible(loginOption, 1000)) {
      await loginOption.first().click();
      await page.waitForLoadState('domcontentloaded').catch(() => {});
    }
    await page.waitForLoadState('networkidle').catch(() => {});
    await unlockIfLocked(page);
    if (!(await hasVisible(page, nameFields))) {
      await page.goto(`${vaultwardenUrl}/#/vault/add`);
      await page.waitForLoadState('domcontentloaded');
      await page.waitForLoadState('networkidle').catch(() => {});
      await unlockIfLocked(page);
      if (!(await hasVisible(page, nameFields))) {
        await writeDiagnostics(page, 'vault-add-form-not-visible-after-unlock');
      }
    }
  }

  await fillFirstVisible(
    page,
    nameFields,
    vaultwardenItemName,
    'Vaultwarden item name field',
  );
  await fillFirstVisible(page, [page.locator(usernameSelector)], appUsername, 'Vaultwarden item username field');
  await fillFirstVisible(page, [page.locator(passwordSelector)], appPassword, 'Vaultwarden item password field');


  await clickFirstVisible(
    page,
    [
      page.getByRole('button', { name: /save|сохранить/i }),
      page.locator('button[type="submit"], input[type="submit"]'),
    ],
    'Vaultwarden save item button',
  );
  await expect(page.locator('body')).toContainText(vaultwardenItemName, { timeout: 30_000 });
}

module.exports = async function globalSetup() {
  if (process.env.SKIP_VAULTWARDEN_SETUP === '1') {
    return;
  }
  if (allowVaultwardenFallback) {
    return;
  }

  const browser = await chromium.launch();
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();
  try {
    if (!(await tryLoginOrUnlock(page))) {
      if (allowVaultwardenRegister) {
        await maybeRegisterAccount(page);
      }
      if (!(await tryLoginOrUnlock(page))) {
        await writeDiagnostics(page, 'vaultwarden-login-required');
        if (await hasInsecureURLToast(page)) {
          // Do not fail the full run here: Profile C test has a runtime fallback path.
          return;
        }
        throw new Error(
          'Vaultwarden login failed in global setup. Check VAULTWARDEN_EMAIL / VAULTWARDEN_MASTER_PASSWORD, or set VAULTWARDEN_ALLOW_REGISTER=1 for account bootstrap.',
        );
      }
    }
    if (!(await itemExists(page))) {
      await createLoginItem(page);
    }
  } finally {
    await context.close();
    await browser.close();
  }
};
