#!/usr/bin/env python3
from __future__ import annotations

import http.cookiejar
import json
import re
import ssl
import sys
import urllib.parse
import urllib.request
from dataclasses import dataclass


@dataclass
class AuthConfig:
    app_url: str
    kc_url: str
    realm: str
    client_id: str
    client_secret: str
    username: str
    password: str


def insecure_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def make_opener(jar: http.cookiejar.CookieJar) -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=insecure_context()),
        urllib.request.HTTPCookieProcessor(jar),
    )


def get_sess_from_profile_c(cfg: AuthConfig) -> str:
    jar = http.cookiejar.CookieJar()
    opener = make_opener(jar)
    body = urllib.parse.urlencode({"email": cfg.username, "password": cfg.password}).encode()
    req = urllib.request.Request(cfg.app_url.rstrip("/") + "/login", data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    opener.open(req, timeout=15).read()
    for c in jar:
        if c.name == "sess":
            return c.value
    return ""


def get_sess_from_profile_a(cfg: AuthConfig) -> str:
    jar = http.cookiejar.CookieJar()
    opener = make_opener(jar)

    # Start OIDC flow.
    resp = opener.open(cfg.app_url.rstrip("/") + "/login", timeout=20)
    html = resp.read().decode("utf-8", errors="ignore")
    final_url = resp.geturl()

    if "keycloak" not in final_url:
        for c in jar:
            if c.name == "sess":
                return c.value
        return ""

    action_match = re.search(r'<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"', html)
    if not action_match:
        return ""
    action_url = html_unescape(action_match.group(1))
    action_url = urllib.parse.urljoin(final_url, action_url)

    payload = {}
    for name, value in re.findall(r'<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"', html):
        payload[name] = html_unescape(value)
    payload["username"] = cfg.username
    payload["password"] = cfg.password

    post = urllib.parse.urlencode(payload).encode()
    req = urllib.request.Request(action_url, data=post, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    opener.open(req, timeout=20).read()

    for c in jar:
        if c.name == "sess":
            return c.value
    return ""


def get_id_token(cfg: AuthConfig) -> str:
    token_url = f"{cfg.kc_url.rstrip('/')}/realms/{cfg.realm}/protocol/openid-connect/token"
    data = urllib.parse.urlencode(
        {
            "grant_type": "password",
            "client_id": cfg.client_id,
            "client_secret": cfg.client_secret,
            "username": cfg.username,
            "password": cfg.password,
            "scope": "openid profile email",
        }
    ).encode()
    req = urllib.request.Request(token_url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=insecure_context()))
    with opener.open(req, timeout=15) as resp:
        payload = json.loads(resp.read().decode("utf-8", errors="ignore"))
    return payload.get("id_token", "")


def html_unescape(s: str) -> str:
    return (
        s.replace("&amp;", "&")
        .replace("&quot;", '"')
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
    )


def main() -> None:
    if len(sys.argv) < 3:
        print("Usage: auto_auth.py <sess|id_token> <json_config>", file=sys.stderr)
        sys.exit(1)

    mode = sys.argv[1]
    cfg_raw = json.loads(sys.argv[2])
    cfg = AuthConfig(
        app_url=cfg_raw["app_url"],
        kc_url=cfg_raw.get("kc_url", "http://keycloak.local:8080"),
        realm=cfg_raw.get("realm", "profile-a-vulnerable"),
        client_id=cfg_raw.get("client_id", "sso-test-app"),
        client_secret=cfg_raw.get("client_secret", "testpass123"),
        username=cfg_raw.get("username", "testuser@example.com"),
        password=cfg_raw.get("password", "password123"),
    )

    if mode == "id_token":
        print(get_id_token(cfg))
        return

    if "app-c" in cfg.app_url:
        print(get_sess_from_profile_c(cfg))
        return
    print(get_sess_from_profile_a(cfg))


if __name__ == "__main__":
    main()
