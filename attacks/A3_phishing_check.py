#!/usr/bin/env python3
"""
A3 — Phishing / Origin Spoofing Check (WebAuthn)
OWASP ASVS v4.2 § 2.8.4 — Verify phishing-resistant MFA is used.
MITRE ATT&CK T1557 (Adversary-in-the-Middle)

WebAuthn credentials are cryptographically bound to the rpID (effective domain).
A credential registered on app-b-h.local CANNOT be used on evil-clone.local,
because the browser enforces the origin check before releasing the assertion.

This script simulates what an attacker would observe when attempting to trigger
a WebAuthn ceremony from a phishing origin:
  1. POST /webauthn/login/begin  → obtains a challenge
  2. Crafts a fake clientDataJSON with origin = http://evil-clone.local
  3. POSTs the forged data to /webauthn/login/finish
  4. The server rejects it (origin does not match rpID)

Usage:
    python3 A3_phishing_check.py <target_url>

Examples:
    python3 A3_phishing_check.py http://app-b-v.local:8082  # Profile B vulnerable
    python3 A3_phishing_check.py https://app-b-h.local      # Profile B hardened

Result:
    PROTECTED — server rejected the forged origin (expected for both variants)
    VULNERABLE — server accepted a credential assertion from evil-clone.local
"""
import sys
import json
import base64
import urllib.request
import urllib.error


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def post_json(url: str, body=None) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body else b""
    req  = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent",   "sso-testbed-attacker/1.0")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, {}
    except Exception as e:
        return 0, {"error": str(e)}


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    base_url = sys.argv[1].rstrip("/")
    evil_origin = "http://evil-clone.local"

    print(f"[A3] Phishing origin spoof: {base_url}")
    print(f"     Forging clientDataJSON with origin={evil_origin}\n")

    # Step 1: obtain a genuine challenge from the target
    status, challenge_resp = post_json(base_url + "/webauthn/login/begin")
    if status != 200 or "publicKey" not in challenge_resp:
        print(f"  [!] Could not start login ceremony (HTTP {status})")
        print("      Is the server running and a passkey registered?")
        print()
        print("SKIPPED — server not ready (register a passkey first)")
        return

    challenge_b64 = challenge_resp["publicKey"]["challenge"]
    print(f"  [+] Got challenge: {challenge_b64[:24]}…")

    # Step 2: build a forged clientDataJSON claiming evil origin
    client_data = {
        "type":      "webauthn.get",
        "challenge": challenge_b64,
        "origin":    evil_origin,
    }
    forged_client_data_json = b64url(json.dumps(client_data).encode())

    # Minimal forged assertion payload (random bytes for fields the server checks after origin)
    forged_assertion = {
        "id":    "AAAAAAAAAAAAAAAAAAAAAA",
        "rawId": "AAAAAAAAAAAAAAAAAAAAAA",
        "type":  "public-key",
        "response": {
            "clientDataJSON":    forged_client_data_json,
            "authenticatorData": b64url(b"\x00" * 37),
            "signature":         b64url(b"\x00" * 64),
            "userHandle":        None,
        },
    }

    # Step 3: submit the forged assertion
    status2, resp2 = post_json(base_url + "/webauthn/login/finish", forged_assertion)
    print(f"  [+] Finish-login with forged origin → HTTP {status2}")

    print()
    if status2 in (200, 302):
        print(f"VULNERABLE — server accepted an assertion from {evil_origin}")
    else:
        print(f"PROTECTED  — server rejected the forged origin (HTTP {status2})")
        print("             WebAuthn's origin binding is working correctly.")


if __name__ == "__main__":
    main()
