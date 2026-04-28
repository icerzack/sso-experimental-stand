#!/usr/bin/env python3

from __future__ import annotations

import math
from pathlib import Path
from typing import Dict, Tuple

import numpy as np
import pandas as pd
from scipy import stats


ROOT = Path(__file__).resolve().parents[1]
DATA_CSV = ROOT / "results" / "processed" / "runs.csv"
INTEGRATION_CSV = ROOT / "results" / "processed" / "integration.csv"

OUT_DIR = ROOT / "analysis" / "out"
FIG_DIR = OUT_DIR / "figures"
REPORT_MD = ROOT / "analysis" / "analysis_report.md"


def cliffs_delta(x: np.ndarray, y: np.ndarray) -> float:
    # Cliff's delta: P(x>y) - P(x<y)
    x = np.asarray(x, dtype=float)
    y = np.asarray(y, dtype=float)
    x = x[~np.isnan(x)]
    y = y[~np.isnan(y)]
    if len(x) == 0 or len(y) == 0:
        return float("nan")
    gt = 0
    lt = 0
    for xv in x:
        gt += np.sum(xv > y)
        lt += np.sum(xv < y)
    return float((gt - lt) / (len(x) * len(y)))


def bootstrap_ci(values: np.ndarray, fn=np.mean, n: int = 2000, alpha: float = 0.05, seed: int = 42) -> Tuple[float, float]:
    rng = np.random.default_rng(seed)
    values = np.asarray(values, dtype=float)
    values = values[~np.isnan(values)]
    if len(values) == 0:
        return float("nan"), float("nan")
    stats_ = []
    for _ in range(n):
        sample = rng.choice(values, size=len(values), replace=True)
        stats_.append(fn(sample))
    lo = float(np.quantile(stats_, alpha / 2))
    hi = float(np.quantile(stats_, 1 - alpha / 2))
    return lo, hi


def choose_test(x: np.ndarray, y: np.ndarray) -> Dict[str, object]:
    x = np.asarray(x, dtype=float)
    y = np.asarray(y, dtype=float)
    x = x[~np.isnan(x)]
    y = y[~np.isnan(y)]
    if len(x) < 3 or len(y) < 3:
        return {"test": "insufficient_samples", "p_value": float("nan")}

    # Normality check (Shapiro is ok for small-ish n; for large n it's too sensitive).
    try:
        px = stats.shapiro(x).pvalue if len(x) <= 5000 else 0.0
        py = stats.shapiro(y).pvalue if len(y) <= 5000 else 0.0
    except Exception:
        px = 0.0
        py = 0.0

    normal = (px > 0.05) and (py > 0.05)
    if normal:
        res = stats.ttest_ind(x, y, equal_var=False)
        return {"test": "welch_t_test", "p_value": float(res.pvalue), "normality_p": (float(px), float(py))}
    res = stats.mannwhitneyu(x, y, alternative="two-sided")
    return {"test": "mann_whitney_u", "p_value": float(res.pvalue), "normality_p": (float(px), float(py))}

def safe_nanmean(values: np.ndarray) -> float:
    values = np.asarray(values, dtype=float)
    values = values[np.isfinite(values)]
    if len(values) == 0:
        return float("nan")
    return float(np.mean(values))

def simple_markdown_table(df: pd.DataFrame) -> str:
    # Minimal markdown table renderer without optional deps.
    cols = list(df.columns)
    rows = df.values.tolist()
    def cell(x):
        if x is None or (isinstance(x, float) and (math.isnan(x) or math.isinf(x))):
            return ""
        return str(x)
    out = []
    out.append("| " + " | ".join(cols) + " |")
    out.append("| " + " | ".join(["---"] * len(cols)) + " |")
    for r in rows:
        out.append("| " + " | ".join(cell(v) for v in r) + " |")
    return "\n".join(out) + "\n"


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    FIG_DIR.mkdir(parents=True, exist_ok=True)

    if not DATA_CSV.exists():
        raise SystemExit(f"Missing dataset: {DATA_CSV}. Run results/processed/build_dataset.py first.")

    df = pd.read_csv(DATA_CSV)

    # Use p95 as the main latency signal for comparisons in the report.
    df["latency_ms"] = df["login_p95_ms"]
    df["throughput_rps"] = pd.to_numeric(df["throughput_rps"], errors="coerce")
    df["error_rate"] = pd.to_numeric(df["error_rate"], errors="coerce")

    # Summary table by (scenario, concurrency, protocol)
    agg = (
        df.groupby(["scenario", "concurrency", "protocol"])
        .agg(
            runs=("run_id", "count"),
            latency_p95_ms_mean=("latency_ms", "mean"),
            latency_p95_ms_min=("latency_ms", "min"),
            latency_p95_ms_max=("latency_ms", "max"),
            error_rate_mean=("error_rate", "mean"),
            throughput_rps_mean=("throughput_rps", "mean"),
            token_size_avg_bytes_mean=("token_size_avg_bytes", "mean"),
            app_login_duration_avg_ms_mean=("app_login_duration_avg_ms", "mean"),
            keycloak_cpu_total_s_mean=("keycloak_cpu_total_s", "mean"),
            keycloak_mem_peak_mb_mean=("keycloak_mem_peak_mb", "mean"),
        )
        .reset_index()
        .sort_values(["scenario", "concurrency", "protocol"])
    )

    # Hypothesis tests: compare SAML vs OIDC per (scenario, concurrency) on per-run p95
    tests = []
    for (scenario, conc), g in df.groupby(["scenario", "concurrency"]):
        x = g.loc[g["protocol"] == "saml", "latency_ms"].to_numpy()
        y = g.loc[g["protocol"] == "oidc", "latency_ms"].to_numpy()
        if len(x) == 0 or len(y) == 0:
            continue
        test = choose_test(x, y)
        cd = cliffs_delta(x, y)
        x_ci = bootstrap_ci(x, np.mean)
        y_ci = bootstrap_ci(y, np.mean)
        tests.append(
            {
                "scenario": scenario,
                "concurrency": int(conc),
                "test": test["test"],
                "p_value": test["p_value"],
                "cliffs_delta": cd,
                "saml_mean_p95_ms": safe_nanmean(x),
                "oidc_mean_p95_ms": safe_nanmean(y),
                "saml_mean_ci_lo": x_ci[0],
                "saml_mean_ci_hi": x_ci[1],
                "oidc_mean_ci_lo": y_ci[0],
                "oidc_mean_ci_hi": y_ci[1],
            }
        )
    tests_df = pd.DataFrame(tests).sort_values(["scenario", "concurrency"])

    # Plots
    try:
        import matplotlib.pyplot as plt
        import seaborn as sns

        sns.set_theme(style="whitegrid")

        # p95 latency vs concurrency
        plt.figure(figsize=(10, 5))
        sns.lineplot(
            data=df,
            x="concurrency",
            y="latency_ms",
            hue="protocol",
            style="scenario",
            markers=True,
            dashes=False,
            errorbar=("ci", 95),
        )
        plt.title("Latency p95 (per-run) vs concurrency")
        plt.ylabel("p95 latency (ms)")
        plt.tight_layout()
        plt.savefig(FIG_DIR / "latency_p95_vs_concurrency.png", dpi=160)
        plt.close()

        # error rate vs concurrency
        plt.figure(figsize=(10, 5))
        sns.lineplot(
            data=df,
            x="concurrency",
            y="error_rate",
            hue="protocol",
            style="scenario",
            markers=True,
            dashes=False,
            errorbar=("ci", 95),
        )
        plt.title("Error rate vs concurrency")
        plt.ylabel("http_req_failed rate")
        plt.tight_layout()
        plt.savefig(FIG_DIR / "error_rate_vs_concurrency.png", dpi=160)
        plt.close()

        # boxplot latency by protocol (facet by scenario)
        plt.figure(figsize=(12, 5))
        sns.boxplot(data=df, x="scenario", y="latency_ms", hue="protocol")
        plt.title("Latency p95 distribution by scenario and protocol (per-run)")
        plt.ylabel("p95 latency (ms)")
        plt.tight_layout()
        plt.savefig(FIG_DIR / "latency_p95_boxplot.png", dpi=160)
        plt.close()
    except Exception:
        # Plotting is optional for headless/CI; report still generated.
        pass

    # Integrability/admin table (optional manual fill)
    if INTEGRATION_CSV.exists():
        integ = pd.read_csv(INTEGRATION_CSV)
    else:
        integ = pd.DataFrame()

    # Write tables to CSV for convenience
    agg.to_csv(OUT_DIR / "aggregates.csv", index=False)
    tests_df.to_csv(OUT_DIR / "tests.csv", index=False)

    # Generate report markdown
    def md_table(d: pd.DataFrame, max_rows: int = 50) -> str:
        if d.empty:
            return "_No data._\n"
        head = d.head(max_rows)
        try:
            return head.to_markdown(index=False) + "\n"
        except Exception:
            return simple_markdown_table(head)

    report = []
    report.append("# SAML vs OIDC: experiment analysis report\n")
    report.append("## Inputs\n")
    report.append(f"- Dataset: `{DATA_CSV}`\n")
    report.append(f"- Figures: `{FIG_DIR}`\n")
    report.append("\n## Quantitative results (performance)\n")
    report.append("### Aggregates (mean/min/max over runs)\n")
    report.append("Includes k6 metrics (latency, throughput, error rate) and Prometheus metrics (app-side login duration, Keycloak CPU/memory).\n")
    report.append("\n**Note on NaN values:**\n")
    report.append("- `app_login_duration_avg_ms`: NaN if the metric was not updated during the run (all values were 0)\n")
    report.append("- `keycloak_cpu_total_s`: NaN if Keycloak doesn't export this metric\n")
    report.append("- `token_size_avg_bytes`: NaN if the metric was not updated during the run (all values were 0)\n")
    report.append("- `keycloak_mem_peak_mb`: Available (aggregated across all JVM heap areas)\n\n")
    report.append(md_table(agg))
    report.append("\n### Hypothesis tests (per scenario, concurrency)\n")
    report.append("We compare **per-run p95 latency** distributions for SAML vs OIDC.\n\n")
    report.append(md_table(tests_df))
    report.append("\n## Qualitative results (integrability/admin)\n")
    report.append("Fill `results/processed/integration.csv` during manual Keycloak admin scenario exercises.\n\n")
    report.append(md_table(integ))
    report.append("\n## Recommendations (template)\n")
    report.append("- Server-rendered web apps: choose based on latency/error profile and operational constraints.\n")
    report.append("- SPA/mobile: typically prefer OIDC due to client ecosystem; validate with your measured overhead.\n")
    report.append("- B2B SSO: SAML can be required by partners; invest in diagnostics and metadata/cert rotation procedures.\n")

    REPORT_MD.write_text("".join(report), encoding="utf-8")
    print(f"Wrote report: {REPORT_MD}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


