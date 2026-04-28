# SSO Experimental Stand

Comparative testbed for three Single Sign-On architectural models,
each available in a **vulnerable** and a **hardened** configuration.

---

## Architectural Profiles


| Profile | Technology               | IdP                     | Auth Protocol               |
| ------- | ------------------------ | ----------------------- | --------------------------- |
| **A**   | Go app + Keycloak 25     | Keycloak                | OIDC / OAuth 2.0 + PKCE     |
| **B**   | Go app (no external IdP) | Built-in WebAuthn store | WebAuthn / FIDO2 (passkeys) |
| **C**   | Go app + Vaultwarden     | Vaultwarden backend     | Session-cookie auth gateway |


Each profile lives under `profile-{a,b,c}/{vulnerable,hardened}/` as a
self-contained Docker Compose stack.

---

## Requirements


| Tool           | Min version           |
| -------------- | --------------------- |
| Docker Engine  | 24                    |
| Docker Compose | v2.24                 |
| Python 3       | 3.10 (attack scripts) |
| Node.js        | 18 (Playwright)       |
| bash / curl    | any                   |


---

## /etc/hosts

All variants use named virtual hosts.
We use a stable naming convention:

- vulnerable: `app-<profile>-v.local`
- hardened: `app-<profile>-h.local`

Add the following entries once:

```
127.0.0.1  app-a-v.local
127.0.0.1  app-a-h.local
127.0.0.1  app-b-v.local
127.0.0.1  app-b-h.local
127.0.0.1  app-c-v.local
127.0.0.1  app-c-h.local
127.0.0.1  keycloak.local
127.0.0.1  evil-clone.local
```

Verify with `make hosts-check`.

You can manage entries automatically:

```bash
make hosts-add      # append missing required host records
make hosts-remove   # remove project host records after testing
```

---

## Quick Start

```bash
# Profile A — vulnerable
make up-a-vuln
# → App:      http://app-a-v.local:8081
# → Keycloak: http://localhost:8080

# Profile A — hardened
make up-a-hard
# → App:      https://app-a-h.local  (Caddy TLS)
# → Keycloak: https://keycloak.local

# Profile B — vulnerable
make up-b-vuln
# → App: http://app-b-v.local:8082

# Profile B — hardened
make up-b-hard
# → App: https://app-b-h.local  (Caddy TLS)

# Profile C — vulnerable
make up-c-vuln
# → App: http://app-c-v.local:8083

# Profile C — hardened
make up-c-hard
# → App: https://app-c-h.local  (Nginx + self-signed TLS)
#   Generate certs first: bash profile-c/hardened/nginx/gen-certs.sh

# Stop everything
make down
```

---

## Default Credentials


| Profile | Variant               | Username / E-mail      | Password      |
| ------- | --------------------- | ---------------------- | ------------- |
| A       | vulnerable & hardened | `testuser1`            | `password123` |
| A       | Keycloak admin        | `admin`                | `admin`       |
| B       | —                     | (passkey, no password) | —             |
| C       | vulnerable            | `testuser@example.com` | `password123` |
| C       | hardened              | `testuser@example.com` | `password123` |


---

## Running Attack Scripts

```bash
# All attacks against whichever Profile A variant is running
make attack-a

# Override target URL for the hardened variant
APP_A=https://app-a-h.local KC_A=https://keycloak.local make attack-a

# Profile B attacks
make attack-b

# Profile C attacks
make attack-c

# Everything
make attack-all
```

Individual scripts accept positional arguments; inspect the header
comments in each file for usage and examples.

---

## Attack Coverage Matrix

**Legend:** VULN = expected to succeed on this variant ·
PROT = expected to be blocked · N/A = attack vector does not apply ·
SPOF = single point of failure observed


| ID  | Script                      | Attack                                              | A-vuln | A-hard | B-vuln | B-hard | C-vuln | C-hard |
| --- | --------------------------- | --------------------------------------------------- | ------ | ------ | ------ | ------ | ------ | ------ |
| A1  | `A1_brute_force.py`         | Brute-force login                                   | VULN   | PROT   | VULN   | PROT   | VULN   | PROT   |
| A2  | `A2_credential_stuffing.py` | Credential stuffing                                 | VULN   | PROT   | N/A    | N/A    | VULN   | PROT   |
| A3  | `A3_phishing_check.py`      | WebAuthn origin-spoof phishing                      | N/A    | N/A    | PROT   | PROT   | N/A    | N/A    |
| A4  | `A4_token_replay.sh`        | Session replay after logout                         | VULN   | PROT   | VULN   | PROT   | N/A    | N/A    |
| A5  | `A5_jwt_algnone.sh`         | JWT `alg=none` (unsigned token)                     | VULN   | PROT   | N/A    | N/A    | N/A    | N/A    |
| A6  | `A6_session_hijack.sh`      | Cookie flag audit + UA replay                       | VULN   | PROT   | VULN   | PROT   | N/A    | N/A    |
| A7  | `A7_redirect_uri.sh`        | Open redirect via `redirect_uri`                    | VULN   | PROT   | N/A    | N/A    | N/A    | N/A    |
| A8  | `A8_csrf_state.sh`          | CSRF — missing `state` + PKCE                       | VULN   | PROT   | N/A    | N/A    | N/A    | N/A    |
| A9  | `A9_open_redirect.sh`       | Open redirect — `strings.Contains` domain confusion | VULN   | PROT   | VULN   | PROT   | N/A    | N/A    |
| A10 | `A10_idp_spof.sh`           | IdP single point of failure                         | SPOF   | SPOF   | N/A    | N/A    | N/A    | N/A    |
| A11 | `A11_db_leak.sh`            | Database / secret leak                              | MED    | LOW    | N/A    | N/A    | CRIT   | OK     |
| A12 | `A12_security_headers.sh`   | Missing HTTP security headers                       | VULN   | PROT   | VULN   | PROT   | VULN   | PROT   |


> **A10 note:** Both Profile A variants are SPOF because the application
> cannot authenticate without Keycloak. Architectural mitigation would
> require Keycloak HA or a fallback IdP — out of scope for this stand.
>
> **A3 note:** WebAuthn's origin binding is a protocol-level guarantee;
> both Profile B variants are expected PROTECTED. The test confirms the
> guarantee holds regardless of configuration.

---

## OWASP / RFC Reference Table


| Attack                 | Standard                     | Section / Requirement                                   |
| ---------------------- | ---------------------------- | ------------------------------------------------------- |
| A1 Brute-force         | OWASP ASVS v4.2              | § 2.2.1 — Verify lockout after ≤ 10 failed attempts     |
| A1 Brute-force         | OWASP Top 10 2021            | A07 Identification and Authentication Failures          |
| A2 Credential stuffing | OWASP ASVS v4.2              | § 2.2.2 — Verify anti-automation controls               |
| A3 WebAuthn phishing   | W3C WebAuthn Level 2         | § 7.2 — rpId binding and origin validation              |
| A3 WebAuthn phishing   | FIDO2 Specification          | RP ID must match document origin                        |
| A4 Token replay        | OWASP ASVS v4.2              | § 3.3.1 — Verify logout invalidates session server-side |
| A4 Token replay        | MITRE ATT&CK                 | T1550.004 — Web Session Cookie                          |
| A5 JWT alg=none        | OWASP ASVS v4.2              | § 3.5.3 — Verify JWTs validate algorithm                |
| A5 JWT alg=none        | RFC 7519                     | § 10.7 — Unsecured JWTs                                 |
| A5 JWT alg=none        | CVE-2015-9235                | `alg=none` confusion in `jsonwebtoken`                  |
| A6 Cookie hijack       | OWASP ASVS v4.2              | § 3.4.1–3.4.5 — Cookie security attributes              |
| A6 Cookie hijack       | MITRE ATT&CK                 | T1539 — Steal Web Session Cookie                        |
| A7 Redirect URI        | RFC 6749                     | § 10.6 — Open Redirectors                               |
| A7 Redirect URI        | OWASP ASVS v4.2              | § 3.5.2 — Verify redirect URIs are validated            |
| A8 CSRF / state        | RFC 6749                     | § 10.12 — Cross-Site Request Forgery                    |
| A8 CSRF / state        | OWASP ASVS v4.2              | § 3.5.3 — Verify `state` parameter integrity            |
| A8 PKCE                | RFC 7636                     | § 4 — Proof Key for Code Exchange                       |
| A9 Open redirect       | OWASP ASVS v4.2              | § 5.1.5 — Verify redirect targets against an allowlist  |
| A9 Open redirect       | CWE-601                      | URL Redirection to Untrusted Site                       |
| A10 IdP SPOF           | OWASP ASVS v4.2              | § 9.2.2 — Availability of authentication service        |
| A10 IdP SPOF           | MITRE ATT&CK                 | T1499 — Endpoint Denial of Service                      |
| A11 DB leak            | OWASP ASVS v4.2              | § 6.2 — Algorithms / § 9.1.1 Secrets at rest            |
| A11 DB leak            | MITRE ATT&CK                 | T1552 — Unsecured Credentials                           |
| A12 Headers            | OWASP ASVS v4.2              | § 14.4 — HTTP Security Headers                          |
| A12 Headers            | OWASP Secure Headers Project | HSTS, CSP, X-Frame-Options, X-Content-Type-Options      |


---

## E2E Tests (Playwright)

```bash
npm install

# Required baseline for Playwright metrics:
# 1) bring up ALL hardened profiles
# 2) run Playwright against hardened domains
bash profile-c/hardened/nginx/gen-certs.sh
make up-a-hard
make up-b-hard
make up-c-hard

# optional safety check
make hosts-check

# run full suite
npx playwright test

# run per profile (hardened)
PROFILE_A_URL=https://app-a-h.local npx playwright test --grep "Profile A"
PROFILE_B_URL=https://app-b-h.local npx playwright test --grep "Profile B"
PROFILE_C_URL=https://app-c-h.local npx playwright test --grep "Profile C"

# shutdown when done
make down
```

Reports are written to `results/playwright/`.

### What Playwright validates

For each profile, tests verify usability and auth flow correctness:

1. unauthenticated user cannot stay on `/protected`;
2. valid login/auth flow reaches `/protected`;
3. profile-specific negative check (for example wrong password on Profile C).

---

## Directory Layout

```
sso-experimental-stand/
├── profile-a/
│   ├── vulnerable/
│   │   ├── app/
│   │   │   ├── main.go             ← Go OIDC app (insecure config)
│   │   │   └── Dockerfile
│   │   ├── keycloak/
│   │   │   └── realm-export.json   ← bruteForceProtected=false, redirectUris=["*"]
│   │   ├── docker-compose.yml
│   │   └── .env
│   └── hardened/
│       ├── app/
│       │   ├── main.go             ← Go OIDC app (PKCE, state, security headers)
│       │   └── Dockerfile
│       ├── keycloak/
│       │   └── realm-export.json   ← bruteForceProtected=true, PKCE S256 required
│       ├── caddy/
│       │   └── Caddyfile           ← TLS termination + security headers
│       ├── docker-compose.yml
│       └── .env
├── profile-b/
│   ├── vulnerable/
│   │   ├── app/
│   │   │   ├── main.go             ← Go WebAuthn app (no rate limit, weak cookies)
│   │   │   └── Dockerfile
│   │   ├── docker-compose.yml
│   │   └── .env
│   └── hardened/
│       ├── app/
│       │   ├── main.go             ← Go WebAuthn app (rate limiter, secure cookies)
│       │   └── Dockerfile
│       ├── caddy/
│       │   └── Caddyfile
│       ├── docker-compose.yml
│       └── .env
├── profile-c/
│   ├── vulnerable/
│   │   ├── app/
│   │   │   ├── main.go             ← Go login app (weak cookie, no rate limit)
│   │   │   └── Dockerfile
│   │   ├── docker-compose.yml      ← Go app + Vaultwarden backend
│   │   └── .env
│   └── hardened/
│       ├── app/
│       │   ├── main.go             ← Go login app (rate limit, secure cookie, headers)
│       │   └── Dockerfile
│       ├── nginx/
│       │   ├── nginx.conf          ← TLS + security headers, proxy to Go app
│       │   ├── gen-certs.sh        ← generate self-signed cert for app-c-h.local
│       │   └── certs/              ← generated at runtime, not committed
│       ├── docker-compose.yml      ← Go app + Vaultwarden backend + Nginx
│       └── .env
├── attacks/
│   ├── A1_brute_force.py
│   ├── A2_credential_stuffing.py
│   ├── A3_phishing_check.py
│   ├── A4_token_replay.sh
│   ├── A5_jwt_algnone.sh
│   ├── A6_session_hijack.sh
│   ├── A7_redirect_uri.sh
│   ├── A8_csrf_state.sh
│   ├── A9_open_redirect.sh
│   ├── A10_idp_spof.sh
│   ├── A11_db_leak.sh
│   └── A12_security_headers.sh
├── wordlists/
│   └── top100_passwords.txt
├── tests/
│   └── e2e/
│       └── auth-profiles.spec.js
├── results/
│   ├── raw/
│   ├── processed/
│   └── playwright/
├── go.mod
├── go.sum
├── Makefile
├── playwright.config.js
└── README.md
```

---

## Results Methodology

1. Start a profile variant (`make up-a-vuln`) and wait for health checks to pass.
2. Run the relevant attack scripts (`make attack-a`) and capture stdout to
  `results/raw/<date>_<profile>_<variant>.txt`.
3. Record VULNERABLE / PROTECTED / N/A per row in the coverage matrix above.
4. Stop the variant (`make down-a`) and repeat for the hardened configuration.
5. Run Playwright smoke tests to verify the authenticated flow is functional
  for each variant under test.
6. Compile findings into `results/processed/` for the thesis appendix.

---

## GitHub CI/CD

Workflow: `.github/workflows/security-stand.yml`

Pipeline stages:

1. Build all images for A/B/C vulnerable+hardened stacks.
2. Run all six variants sequentially (`a-vuln`, `a-hard`, `b-vuln`, `b-hard`, `c-vuln`, `c-hard`).
3. Execute attack suites for each running variant.
4. Aggregate raw logs into machine-readable summary (`results/processed/attack-summary.json`).
5. Generate a one-page landing report (`results/processed/index.html`) with:
   - scope and purpose of the stand;
   - what checks were executed;
   - summarized verdicts;
   - best practices to reduce top attack classes;
   - source links (OWASP, RFCs, WebAuthn, CWE, MITRE).

