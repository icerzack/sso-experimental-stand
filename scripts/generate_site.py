#!/usr/bin/env python3
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path


SITE_DIR = Path("site")
SITE_INDEX = SITE_DIR / "index.html"


def render_html(generated_at: str) -> str:
    return f"""<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>SSO Stand Results</title>
  <style>
    :root {{
      --bg: #f5f7fb;
      --text: #101828;
      --muted: #475467;
      --border: #d0d5dd;
      --card: #ffffff;
      --ok: #067647;
      --warn: #b54708;
      --na: #344054;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.45;
    }}
    .container {{
      max-width: 1100px;
      margin: 0 auto;
      padding: 28px 18px 42px;
    }}
    .card {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 18px;
      margin-bottom: 16px;
    }}
    h1, h2 {{
      margin: 0 0 10px;
      line-height: 1.2;
    }}
    p {{
      margin: 0 0 10px;
      color: var(--muted);
    }}
    .note {{
      border-left: 4px solid #155eef;
      padding: 10px 12px;
      background: #eef4ff;
      border-radius: 8px;
      color: #004eeb;
      font-weight: 600;
    }}
    ul {{
      margin: 8px 0 0;
      padding-left: 18px;
    }}
    li {{ margin: 4px 0; }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 12px;
      font-size: 14px;
    }}
    th, td {{
      border: 1px solid var(--border);
      padding: 8px 10px;
      vertical-align: top;
      text-align: left;
    }}
    thead th {{
      background: #f2f4f7;
    }}
    .ok {{ color: var(--ok); font-weight: 600; }}
    .warn {{ color: var(--warn); font-weight: 600; }}
    .na {{ color: var(--na); font-weight: 600; }}
    .footer {{
      margin-top: 10px;
      color: #667085;
      font-size: 13px;
    }}
    code {{
      background: #eef2ff;
      border: 1px solid #c7d7fe;
      border-radius: 6px;
      padding: 1px 6px;
      font-size: 13px;
      color: #1d4ed8;
    }}
  </style>
</head>
<body>
  <main class="container">
    <section class="card">
      <h1>Результаты SSO experimental stand</h1>
      <p>Эта страница показывает итоговые результаты тестового стенда по безопасности SSO-профилей.</p>
      <p class="note">Важно: для каждого профиля есть два варианта — <strong>vulnerable</strong> (намеренно слабая защита) и <strong>hardened</strong> (включены best-practice меры защиты).</p>
    </section>

    <section class="card">
      <h2>Что тестировалось</h2>
      <ul>
        <li>Устойчивость к brute-force и credential stuffing.</li>
        <li>Replay/hijack сценарии для сессий и токенов.</li>
        <li>OAuth/OIDC проверки на redirect/state/PKCE.</li>
        <li>Архитектурные риски (IdP SPOF, утечки данных/секретов).</li>
        <li>Наличие базовых HTTP security headers.</li>
      </ul>
    </section>

    <section class="card">
      <h2>Как тестировалось</h2>
      <ul>
        <li>Каждый профиль поднимается в Docker Compose в вариантах vulnerable/hardened.</li>
        <li>Запускаются атаки из каталога <code>attacks/</code> и сохраняются сырые логи.</li>
        <li>Логи агрегируются в артефакты CI и публикуются в GitHub Pages.</li>
      </ul>
    </section>

    <section class="card">
      <h2>Как протестировать самостоятельно</h2>
      <ul>
        <li>Поднять нужный вариант, например <code>make up-a-vuln</code> или <code>make up-c-hard</code>.</li>
        <li>Запустить соответствующий набор атак: <code>make attack-a</code>, <code>make attack-b</code>, <code>make attack-c</code>.</li>
        <li>Остановить стенд: <code>make down</code>.</li>
      </ul>
    </section>

    <section class="card">
      <h2>Сводная таблица по профилям (валидировано по текущим скриптам стенда)</h2>
      <table>
        <thead>
          <tr>
            <th>Атака</th>
            <th>Профиль A</th>
            <th>Профиль Б</th>
            <th>Профиль В</th>
          </tr>
        </thead>
        <tbody>
          <tr><td>A1 Brute Force</td><td class="warn">⚠️ vuln/hard</td><td class="na">❌ N/A (нет пароля)</td><td class="warn">⚠️ vuln/hard</td></tr>
          <tr><td>A2 Credential Stuffing</td><td class="warn">⚠️ vuln/hard</td><td class="na">❌ N/A (нет пароля)</td><td class="warn">⚠️ vuln/hard</td></tr>
          <tr><td>A3 Phishing (WebAuthn)</td><td class="na">❌ N/A</td><td class="ok">✅ архит. защищен</td><td class="na">❌ N/A</td></tr>
          <tr><td>B1 Token Replay</td><td class="warn">⚠️ vuln/hard</td><td class="warn">⚠️ vuln/hard</td><td class="na">❌ N/A (нет JWT/сессии A/B формата)</td></tr>
          <tr><td>B2 JWT alg:none</td><td class="warn">⚠️ vuln/hard</td><td class="na">❌ N/A (нет JWT)</td><td class="na">❌ N/A (нет JWT)</td></tr>
          <tr><td>B3 Session Hijacking</td><td class="warn">⚠️ vuln/hard</td><td class="warn">⚠️ vuln/hard</td><td class="na">❌ N/A (в рамках текущего A6 скрипта)</td></tr>
          <tr><td>C1 redirect_uri</td><td class="warn">⚠️ vuln/hard</td><td class="na">❌ N/A (нет OAuth)</td><td class="na">❌ N/A (нет OAuth)</td></tr>
          <tr><td>C2 CSRF/state</td><td class="warn">⚠️ vuln/hard</td><td class="na">❌ N/A (нет OAuth)</td><td class="na">❌ N/A (нет OAuth)</td></tr>
          <tr><td>D1 IdP SPOF</td><td class="warn">⚠️ SPOF в обоих вариантах</td><td class="ok">✅ независим от Keycloak</td><td class="na">❌ N/A (не завязан на Keycloak)</td></tr>
          <tr><td>D2 DB Leak</td><td class="warn">⚠️ vuln/hard (разная тяжесть)</td><td class="na">❌ N/A (нет отдельной DB в тесте)</td><td class="warn">⚠️ vuln/hard</td></tr>
          <tr><td>E1 Security Headers</td><td class="warn">⚠️ vuln/hard</td><td class="warn">⚠️ vuln/hard</td><td class="warn">⚠️ vuln/hard</td></tr>
        </tbody>
      </table>
      <p class="footer">Сгенерировано в CI: {generated_at}</p>
    </section>
  </main>
</body>
</html>
"""


def main() -> None:
    SITE_DIR.mkdir(parents=True, exist_ok=True)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    SITE_INDEX.write_text(render_html(generated_at), encoding="utf-8")
    print(f"Written {SITE_INDEX}")


if __name__ == "__main__":
    main()
