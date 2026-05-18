#!/usr/bin/env python3
"""
generate_e2_report.py — Generate a comparative benchmark report for Experiment 2.

Reads all Prometheus metric exports and k6 results from results/raw/,
produces a single HTML comparison table + charts.

Usage:
    python3 scripts/generate_e2_report.py
"""
from __future__ import annotations

import json
import html
import statistics
from pathlib import Path

RAW_DIR = Path("results/raw")
OUT_DIR = Path("results/processed")
OUT_DIR.mkdir(parents=True, exist_ok=True)
HTML_PATH = OUT_DIR / "e2-benchmark-report.html"
JSON_PATH = OUT_DIR / "e2-benchmark-summary.json"


def load_prometheus_files() -> list[dict]:
    """Load all prometheus-*.json files from results/raw/."""
    files = sorted(RAW_DIR.glob("prometheus-*.json"))
    results = []
    for f in files:
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            if data.get("profile"):
                data["_source"] = f.name
                results.append(data)
        except (json.JSONDecodeError, OSError):
            continue
    return results


def load_k6_files() -> dict[str, dict]:
    """Load k6 result JSON files, keyed by timestamp-ish in filename."""
    files = sorted(RAW_DIR.glob("k6-*.json"))
    results = {}
    for f in files:
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            # Extract VU count and timestamp from filename like k6-50vu-20241201-120000.json
            name = f.stem
            parts = name.split("-")
            vu_key = "?"
            for p in parts:
                if p.endswith("vu"):
                    vu_key = p.replace("vu", "")
            key = f"{f.name}"
            results[key] = data
        except (json.JSONDecodeError, OSError):
            continue
    return results


def load_startup_files() -> dict[str, dict]:
    """Load startup-*.txt files with timing information."""
    files = sorted(RAW_DIR.glob("startup-*.txt"))
    results = {}
    for f in files:
        try:
            content = f.read_text(encoding="utf-8")
            parsed = {}
            for line in content.strip().splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    parsed[k.strip()] = v.strip()
            profile = parsed.get("profile", "unknown")
            results[profile] = parsed
        except OSError:
            continue
    return results


def extract_latency(prom_data: dict, quantile: str) -> str:
    """Extract a scalar latency value from Prometheus export summary."""
    try:
        val = prom_data.get("summary", {}).get(f"latency_{quantile}_s")
        if val is not None:
            return f"{float(val)*1000:.1f} ms"
    except (TypeError, ValueError):
        pass
    return "N/A"


def extract_peak_mem(prom_data: dict, container: str) -> str:
    """Extract peak memory value."""
    try:
        val = prom_data.get("summary", {}).get(f"peak_mem_{container}_mb")
        if val is not None:
            return f"{float(val):.0f} MB"
    except (TypeError, ValueError):
        pass
    return "N/A"


def extract_total_requests(prom_data: dict) -> str:
    """Extract total request count."""
    try:
        val = prom_data.get("summary", {}).get("total_requests")
        if val is not None:
            return f"{float(val):.0f}"
    except (TypeError, ValueError):
        pass
    return "N/A"


def extract_error_rate(prom_data: dict) -> str:
    """Extract error rate as percentage."""
    try:
        val = prom_data.get("summary", {}).get("error_rate")
        if val is not None:
            return f"{float(val)*100:.2f}%"
    except (TypeError, ValueError):
        pass
    return "N/A"


IDP_NAMES = {
    "e2a": "Keycloak",
    "e2b": "Authentik",
    "e2c": "Zitadel",
    "e2d": "Authelia OIDC",
}


def render_html(
    prom_results: list[dict],
    startup_data: dict[str, dict],
) -> str:
    # Group by profile (latest run per profile wins)
    by_profile: dict[str, dict] = {}
    for r in prom_results:
        p = r["profile"]
        by_profile[p] = r  # last one wins (sorted by filename)

    profiles = ["e2a", "e2b", "e2c", "e2d"]

    # Build comparison table rows
    rows_html = ""
    for p in profiles:
        pr = by_profile.get(p)
        st = startup_data.get(p, {})

        idp_name = IDP_NAMES.get(p, p)
        startup_s = st.get("startup_seconds", "N/A")
        first_login_ms = st.get("first_login_ms", "N/A")

        if pr:
            p50 = extract_latency(pr, "p50")
            p95 = extract_latency(pr, "p95")
            p99 = extract_latency(pr, "p99")
            mem_idp = extract_peak_mem(pr, "idp")
            mem_app = extract_peak_mem(pr, "app")
            total_req = extract_total_requests(pr)
            err_rate = extract_error_rate(pr)
        else:
            p50 = p95 = p99 = mem_idp = mem_app = total_req = err_rate = "—"

        rows_html += f"""<tr>
            <td><strong>{html.escape(idp_name)}</strong><br/><small>{p}</small></td>
            <td>{html.escape(str(startup_s))}</td>
            <td>{html.escape(str(first_login_ms))}</td>
            <td>{html.escape(p50)}</td>
            <td>{html.escape(p95)}</td>
            <td>{html.escape(p99)}</td>
            <td>{html.escape(mem_idp)}</td>
            <td>{html.escape(mem_app)}</td>
            <td>{html.escape(total_req)}</td>
            <td>{html.escape(err_rate)}</td>
        </tr>\n"""

    # Count available results
    n_profiles_with_data = len(by_profile)
    n_total_profiles = len(profiles)

    return f"""<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Experiment 2 — IdP Platform Benchmark Report</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 24px; color: #111; background: #fafafa; }}
    h1 {{ margin: 0 0 8px; font-size: 1.6em; }}
    h2 {{ margin: 24px 0 12px; font-size: 1.2em; }}
    .subtitle {{ color: #666; margin-bottom: 20px; }}
    .summary-pills {{ display: flex; gap: 12px; margin: 16px 0 24px; flex-wrap: wrap; }}
    .pill {{ padding: 8px 14px; border-radius: 10px; background: #fff; border: 1px solid #e5e7eb; box-shadow: 0 1px 2px rgba(0,0,0,.05); }}
    .pill strong {{ display: block; font-size: 1.3em; }}
    table {{ width: 100%; border-collapse: collapse; background: #fff; border-radius: 10px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.08); }}
    th {{ background: #f9fafb; padding: 12px; text-align: left; font-size: .85em; text-transform: uppercase; letter-spacing: .05em; color: #6b7280; border-bottom: 2px solid #e5e7eb; }}
    td {{ padding: 12px; border-bottom: 1px solid #f3f4f6; vertical-align: middle; }}
    tr:hover {{ background: #f9fafb; }}
    small {{ color: #9ca3af; }}
    .methodology {{ background: #fff; padding: 16px; border-radius: 10px; border: 1px solid #e5e7eb; margin-top: 24px; }}
    code {{ background: #f3f4f6; padding: 2px 6px; border-radius: 4px; font-size: .9em; }}
  </style>
</head>
<body>
  <h1>Эксперимент 2 — Сравнение производительности IdP-платформ</h1>
  <p class="subtitle">
    Автоматизированный нагрузочный тест: развёртывание → прогрев → k6 (ROPC + Authorization Code Flow) → экспорт метрик → остановка.
    Данные собраны из Prometheus и k6.
  </p>

  <div class="summary-pills">
    <div class="pill">Профилей с данными<strong>{n_profiles_with_data}/{n_total_profiles}</strong></div>
  </div>

  <h2>Сравнительная таблица</h2>
  <table>
    <thead>
      <tr>
        <th>IdP</th>
        <th>Startup, s</th>
        <th>First login, ms</th>
        <th>p50 latency</th>
        <th>p95 latency</th>
        <th>p99 latency</th>
        <th>Peak Mem IdP</th>
        <th>Peak Mem App</th>
        <th>Total req</th>
        <th>Error rate</th>
      </tr>
    </thead>
    <tbody>
      {rows_html}
    </tbody>
  </table>

  <div class="methodology">
    <h2 style="margin-top:0">Методика измерений</h2>
    <ol>
      <li>Развёртывание профиля через <code>docker compose up -d --build</code></li>
      <li>Прогрев — ожидание healthcheck приложения (<code>/healthz → 200</code>)</li>
      <li>Измерение time-to-first-login через ROPC grant</li>
      <li>Нагрузочный тест k6: staircase 10→50→100→200 VU, режим mixed (ROPC + browser flow)</li>
      <li>Экспорт метрик из Prometheus в JSON за окно baseline_start..metrics_end</li>
      <li>Остановка стенда, очистка volumes</li>
    </ol>
    <p>Запуск: <code>make bench-e2-all</code> или <code>./scripts/bench-e2.sh e2a</code></p>
  </div>
</body>
</html>"""


def main() -> None:
    print("Loading raw results...")
    prom_results = load_prometheus_files()
    startup_data = load_startup_files()

    print(f"Found {len(prom_results)} Prometheus exports, {len(startup_data)} startup records")

    html_content = render_html(prom_results, startup_data)

    HTML_PATH.write_text(html_content, encoding="utf-8")
    print(f"HTML report: {HTML_PATH}")

    # Also save structured JSON summary
    summary = []
    for r in prom_results:
        summary.append({
            "profile": r["profile"],
            "summary": r.get("summary", {}),
            "_source": r.get("_source", ""),
        })
    JSON_PATH.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"JSON summary: {JSON_PATH}")


if __name__ == "__main__":
    main()
