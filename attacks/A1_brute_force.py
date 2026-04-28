#!/usr/bin/env python3
"""
A1 — Brute-Force Login
OWASP ASVS v4.2 § 2.2.1 — Verify anti-automation controls exist.
MITRE ATT&CK T1110.001

Usage:
    python3 A1_brute_force.py <base_url> [login_path] [username]

Examples:
    python3 A1_brute_force.py http://app-c-v.local:8083         # Profile C vulnerable
    python3 A1_brute_force.py http://keycloak.local:8080 /kc    # Profile A vulnerable (Keycloak ROPC)

Result:
    VULNERABLE — 20 attempts completed without lockout (no 429/423)
    PROTECTED  — lockout detected within 20 attempts
    N/A        — not applicable (e.g. WebAuthn-only profile)
"""
import sys
import time
import urllib.request
import urllib.parse
import urllib.error
from typing import Tuple

MAX_ATTEMPTS = 20
CREDENTIALS  = [("testuser@example.com", p) for p in [
    "wrong1","wrong2","wrong3","wrong4","wrong5",
    "wrong6","wrong7","wrong8","wrong9","wrong10",
    "wrong11","wrong12","wrong13","wrong14","wrong15",
    "wrong16","wrong17","wrong18","wrong19","wrong20",
]]


def attempt_form(base_url: str, path: str, email: str, password: str) -> Tuple[int, float]:
    url  = base_url.rstrip("/") + path
    data = urllib.parse.urlencode({"email": email, "password": password}).encode()
    req  = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("User-Agent",   "sso-testbed-attacker/1.0")
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
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
        with urllib.request.urlopen(req, timeout=10) as resp:
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
    path     = sys.argv[2] if len(sys.argv) > 2 else ""
    username = sys.argv[3] if len(sys.argv) > 3 else "testuser@example.com"

    # Detect target type
    is_keycloak = "keycloak" in base_url or path == "/kc"
    is_profile_b = "app-b" in base_url

    if is_profile_b:
        print("[A1] Brute-force: N/A for WebAuthn/FIDO2 profiles")
        print("     Profile B uses passkey authentication — no password to brute-force.")
        print()
        print("N/A — brute-force not applicable to WebAuthn profiles")
        return

    if is_keycloak:
        realm = "profile-a-vulnerable"
        client_id = "sso-test-app"
        client_secret = "testpass123"
        if "hard" in base_url:
            realm = "profile-a-hardened"
            client_secret = "Str0ngCl!entS3cr3t_changeme"

        print(f"[A1] Brute-force via Keycloak ROPC: {base_url}")
        print(f"     Realm: {realm}, Client: {client_id}, User: {username}")
        print(f"     Sending {MAX_ATTEMPTS} failed login attempts …\n")

        locked_at = None
        for i, (user, pwd) in enumerate(CREDENTIALS[:MAX_ATTEMPTS], 1):
            status, elapsed = attempt_keycloak(base_url, realm, client_id, client_secret, username, pwd)
            marker = ""
            if status in (429, 423):
                marker = "  ← LOCKOUT"
                locked_at = i
            elif status == 401:
                marker = ""
            print(f"  [{i:02d}] status={status}  {elapsed*1000:.0f}ms{marker}")
            if locked_at:
                break

        print()
        if locked_at:
            print(f"PROTECTED — lockout triggered after {locked_at} attempt(s) (HTTP {status})")
        else:
            print(f"VULNERABLE — {MAX_ATTEMPTS} attempts completed without any lockout response")
        return

    # Form-based login (Profile C Go app)
    if "8083" in base_url or "8084" in base_url or "app-c" in base_url:
        path = "/login"
    elif not path:
        path = "/login"

    print(f"[A1] Brute-force: {base_url}{path}  user={username}")
    print(f"     Sending {MAX_ATTEMPTS} failed login attempts …\n")

    locked_at = None
    for i, (user, pwd) in enumerate(CREDENTIALS[:MAX_ATTEMPTS], 1):
        status, elapsed = attempt_form(base_url, path, username, pwd)
        marker = ""
        if status in (429, 423):
            marker = "  ← LOCKOUT"
            locked_at = i
        print(f"  [{i:02d}] status={status}  {elapsed*1000:.0f}ms{marker}")
        if locked_at:
            break

    print()
    if locked_at:
        print(f"PROTECTED — lockout triggered after {locked_at} attempt(s) (HTTP {status})")
    else:
        print(f"VULNERABLE — {MAX_ATTEMPTS} attempts completed without any lockout response")


if __name__ == "__main__":
    main()
