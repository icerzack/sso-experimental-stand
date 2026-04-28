#!/usr/bin/env python3
from __future__ import annotations

import html
import json
import re
from pathlib import Path


RAW_DIR = Path("results/raw")
PROCESSED_DIR = Path("results/processed")
JSON_PATH = PROCESSED_DIR / "attack-summary.json"
HTML_PATH = PROCESSED_DIR / "index.html"


ATTACK_HEADER_RE = re.compile(r"\[(A\d+)\]\s*(.+)")
VERDICT_RE = re.compile(r"\b(PROTECTED|VULNERABLE|PARTIAL|RESILIENT|INCONCLUSIVE|SKIPPED)\b", re.IGNORECASE)


def parse_raw_file(path: Path) -> dict:
    content = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    attacks = []
    current = None

    for line in content:
        m = ATTACK_HEADER_RE.search(line)
        if m:
            current = {
                "id": m.group(1),
                "name": m.group(2).strip(),
                "verdict": "UNKNOWN",
                "evidence": [],
            }
            attacks.append(current)
            continue

        if not current:
            continue

        vm = VERDICT_RE.search(line)
        if vm:
            current["verdict"] = vm.group(1).upper()
            current["evidence"].append(line.strip())

    return {
        "variant": path.stem,
        "attacks": attacks,
    }


def render_html(summary: list[dict]) -> str:
    total = sum(len(s["attacks"]) for s in summary)
    vuln = sum(1 for s in summary for a in s["attacks"] if a["verdict"] == "VULNERABLE")
    prot = sum(1 for s in summary for a in s["attacks"] if a["verdict"] == "PROTECTED")
    partial = sum(1 for s in summary for a in s["attacks"] if a["verdict"] in {"PARTIAL", "INCONCLUSIVE"})

    cards = []
    for item in summary:
        rows = []
        for attack in item["attacks"]:
            verdict = html.escape(attack["verdict"])
            name = html.escape(f'{attack["id"]}: {attack["name"]}')
            evidence = html.escape(" | ".join(attack["evidence"][:2])) or "No explicit verdict line captured"
            rows.append(
                f"<tr><td>{name}</td><td><strong>{verdict}</strong></td><td>{evidence}</td></tr>"
            )
        table = (
            "<table><thead><tr><th>Attack</th><th>Verdict</th><th>Evidence</th></tr></thead>"
            f"<tbody>{''.join(rows) if rows else '<tr><td colspan=3>No attack logs parsed</td></tr>'}</tbody></table>"
        )
        cards.append(
            f"<section class='card'><h2>{html.escape(item['variant'])}</h2>{table}</section>"
        )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>SSO Experimental Stand Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; color: #111; }}
    h1, h2 {{ margin: 0 0 12px; }}
    .summary {{ display: flex; gap: 12px; margin: 16px 0 24px; flex-wrap: wrap; }}
    .pill {{ padding: 8px 12px; border-radius: 8px; background: #f3f4f6; }}
    .card {{ border: 1px solid #ddd; border-radius: 10px; padding: 14px; margin-bottom: 14px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
    th, td {{ border: 1px solid #e5e7eb; padding: 8px; text-align: left; vertical-align: top; }}
    th {{ background: #f9fafb; }}
    .sources li {{ margin-bottom: 6px; }}
  </style>
</head>
<body>
  <h1>SSO Experimental Stand - Security Validation Report</h1>
  <p>This report summarizes automated attack runs across all six profile variants (A/B/C vulnerable + hardened). The stand compares weak and hardened authentication configurations for OIDC, WebAuthn, and Go gateway patterns.</p>
  <div class="summary">
    <div class="pill">Total parsed attacks: <strong>{total}</strong></div>
    <div class="pill">VULNERABLE findings: <strong>{vuln}</strong></div>
    <div class="pill">PROTECTED findings: <strong>{prot}</strong></div>
    <div class="pill">PARTIAL/INCONCLUSIVE: <strong>{partial}</strong></div>
  </div>
  <h2>What is validated</h2>
  <ul>
    <li>Brute-force and credential stuffing resilience</li>
    <li>Token/session replay and cookie hijack resistance</li>
    <li>OAuth redirect/state/PKCE validation correctness</li>
    <li>IdP SPOF behavior and DB/secret exposure checks</li>
    <li>HTTP security headers hardening baseline</li>
  </ul>
  <h2>Best practices to reduce top attacks</h2>
  <ul>
    <li>Enforce rate limiting and account lockout on auth endpoints.</li>
    <li>Require PKCE + strict state checks for OAuth/OIDC callbacks.</li>
    <li>Use strict redirect allowlists; avoid substring host checks.</li>
    <li>Set secure session cookies: HttpOnly, Secure, SameSite=Strict.</li>
    <li>Add baseline security headers (HSTS, CSP, XFO, XCTO, Referrer-Policy).</li>
    <li>Harden secrets and DB access; avoid plaintext secret exposure.</li>
  </ul>
  <h2>Per-variant results</h2>
  {''.join(cards)}
  <h2>Sources</h2>
  <ul class="sources">
    <li><a href="https://owasp.org/www-project-application-security-verification-standard/" target="_blank">OWASP ASVS</a></li>
    <li><a href="https://owasp.org/Top10/" target="_blank">OWASP Top 10</a></li>
    <li><a href="https://datatracker.ietf.org/doc/html/rfc6749" target="_blank">RFC 6749 (OAuth 2.0)</a></li>
    <li><a href="https://datatracker.ietf.org/doc/html/rfc7636" target="_blank">RFC 7636 (PKCE)</a></li>
    <li><a href="https://datatracker.ietf.org/doc/html/rfc7519" target="_blank">RFC 7519 (JWT)</a></li>
    <li><a href="https://www.w3.org/TR/webauthn-2/" target="_blank">W3C WebAuthn Level 2</a></li>
    <li><a href="https://cwe.mitre.org/data/definitions/601.html" target="_blank">CWE-601 Open Redirect</a></li>
    <li><a href="https://attack.mitre.org/" target="_blank">MITRE ATT&amp;CK</a></li>
  </ul>
</body>
</html>"""


def main() -> None:
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    summary = [parse_raw_file(p) for p in sorted(RAW_DIR.glob("*.txt"))]
    JSON_PATH.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    HTML_PATH.write_text(render_html(summary), encoding="utf-8")
    print(f"Written {JSON_PATH}")
    print(f"Written {HTML_PATH}")


if __name__ == "__main__":
    main()
