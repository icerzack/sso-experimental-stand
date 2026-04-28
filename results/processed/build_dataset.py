#!/usr/bin/env python3

import csv
import json
import math
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


ROOT = Path(__file__).resolve().parents[2]
RAW_DIR = ROOT / "results" / "raw"
OUT_DIR = ROOT / "results" / "processed"


def parse_float(s: str) -> Optional[float]:
    try:
        return float(s)
    except Exception:
        return None


def parse_percent(s: str) -> Optional[float]:
    s = (s or "").strip()
    if s.endswith("%"):
        s = s[:-1]
    return parse_float(s)


def parse_size_to_mb(s: str) -> Optional[float]:
    # Examples: "123.4MiB", "1.23GiB", "456kB", "789B"
    s = (s or "").strip()
    if not s:
        return None
    units = [("KiB", 1024), ("MiB", 1024**2), ("GiB", 1024**3), ("TiB", 1024**4),
             ("kB", 1000), ("MB", 1000**2), ("GB", 1000**3), ("TB", 1000**4),
             ("B", 1)]
    for u, mul in units:
        if s.endswith(u):
            num = parse_float(s[: -len(u)].strip())
            if num is None:
                return None
            return (num * mul) / (1024**2)
    # Fallback: try raw float MB
    return parse_float(s)


def safe_int(x: Any) -> Optional[int]:
    try:
        if x is None:
            return None
        return int(x)
    except Exception:
        return None


def read_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def extract_k6_metric(summary: Dict[str, Any], metric_name: str) -> Optional[Dict[str, Any]]:
    metrics = summary.get("metrics") or {}
    m = metrics.get(metric_name)
    return m if isinstance(m, dict) else None


def extract_k6_value(summary: Dict[str, Any], metric_name: str, key: str) -> Optional[float]:
    m = extract_k6_metric(summary, metric_name)
    if not m:
        return None
    # k6 JSON format: values can be directly in the metric object or in a "values" sub-object
    # First try direct access (most common in k6 JSON output)
    if key in m:
        return parse_float(m[key])
    # Try case-insensitive direct match
    for k, v in m.items():
        if str(k).lower() == key.lower():
            return parse_float(v)
    # Fallback: try "values" sub-object (some k6 formats)
    values = m.get("values") or {}
    if key in values:
        return parse_float(values[key])
    # Try common fallbacks in values (case-insensitive).
    for k, v in values.items():
        if str(k).lower() == key.lower():
            return parse_float(v)
    return None


def prom_delta_sum_count(prom_sum: Dict[str, Any], prom_count: Dict[str, Any], match_labels: Dict[str, str]) -> Tuple[Optional[float], Optional[float]]:
    def pick_series(doc: Dict[str, Any]) -> Optional[List[List[Any]]]:
        data = doc.get("data") or {}
        for res in (data.get("result") or []):
            metric = res.get("metric") or {}
            ok = True
            for k, v in match_labels.items():
                if metric.get(k) != v:
                    ok = False
                    break
            if ok:
                return res.get("values") or None
        return None

    s_vals = pick_series(prom_sum)
    c_vals = pick_series(prom_count)
    if not s_vals or not c_vals:
        return None, None

    def first_last(vals: List[List[Any]]) -> Tuple[Optional[float], Optional[float]]:
        if len(vals) < 2:
            return None, None
        first = parse_float(vals[0][1])
        last = parse_float(vals[-1][1])
        return first, last

    s0, s1 = first_last(s_vals)
    c0, c1 = first_last(c_vals)
    if s0 is None or s1 is None or c0 is None or c1 is None:
        return None, None
    ds = s1 - s0
    dc = c1 - c0
    if ds < 0 or dc < 0:
        return None, None
    return ds, dc


def prom_avg_from_sum_count(prom_sum: Dict[str, Any], prom_count: Dict[str, Any], match_labels: Dict[str, str]) -> Optional[float]:
    """Extract average value from Prometheus sum/count metrics."""
    ds, dc = prom_delta_sum_count(prom_sum, prom_count, match_labels)
    if ds is None or dc is None or dc <= 0:
        return None
    return ds / dc


def prom_delta(prom_doc: Dict[str, Any], match_labels: Dict[str, str]) -> Optional[float]:
    """Extract delta (last - first) from a Prometheus range query."""
    data = prom_doc.get("data") or {}
    for res in (data.get("result") or []):
        metric = res.get("metric") or {}
        ok = True
        for k, v in match_labels.items():
            if metric.get(k) != v:
                ok = False
                break
        if ok:
            values = res.get("values") or []
            if len(values) < 2:
                return None
            first = parse_float(values[0][1])
            last = parse_float(values[-1][1])
            if first is None or last is None:
                return None
            delta = last - first
            return delta if delta >= 0 else None
    return None


def prom_max(prom_doc: Dict[str, Any], match_labels: Dict[str, str]) -> Optional[float]:
    """Extract maximum value from a Prometheus range query."""
    data = prom_doc.get("data") or {}
    max_val = None
    for res in (data.get("result") or []):
        metric = res.get("metric") or {}
        ok = True
        for k, v in match_labels.items():
            if metric.get(k) != v:
                ok = False
                break
        if ok:
            values = res.get("values") or []
            for _, val_str in values:
                val = parse_float(val_str)
                if val is not None:
                    if max_val is None or val > max_val:
                        max_val = val
    return max_val


def docker_stats_avg(path: Path) -> Dict[str, Dict[str, Optional[float]]]:
    # Returns per-container averages: cpu_perc, mem_used_mb
    sums: Dict[str, Dict[str, float]] = {}
    counts: Dict[str, int] = {}
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except Exception:
                continue
            c = row.get("container")
            if not c:
                continue
            cpu = parse_percent(row.get("cpu_perc", ""))
            mem_usage = row.get("mem_usage", "")
            mem_used = None
            if isinstance(mem_usage, str) and "/" in mem_usage:
                mem_used = parse_size_to_mb(mem_usage.split("/", 1)[0].strip())
            if c not in sums:
                sums[c] = {"cpu": 0.0, "mem": 0.0}
                counts[c] = 0
            if cpu is not None:
                sums[c]["cpu"] += cpu
            if mem_used is not None:
                sums[c]["mem"] += mem_used
            counts[c] += 1
    out: Dict[str, Dict[str, Optional[float]]] = {}
    for c, s in sums.items():
        n = counts.get(c) or 0
        if n <= 0:
            continue
        out[c] = {
            "cpu_perc_avg": s["cpu"] / n if n else None,
            "mem_used_mb_avg": s["mem"] / n if n else None,
        }
    return out


@dataclass
class RunRow:
    run_id: str
    timestamp: str
    profile: str
    scenario: str
    concurrency: int
    duration_s: int
    ramp_up_s: int
    repeat_no: int
    seed: Optional[int]
    login_p50_ms: Optional[float]
    login_p95_ms: Optional[float]
    login_p99_ms: Optional[float]
    throughput_rps: Optional[float]
    error_rate: Optional[float]
    redirect_count_avg: Optional[float]
    token_size_avg_bytes: Optional[float]
    keycloak_cpu_avg: Optional[float]
    keycloak_mem_avg_mb: Optional[float]
    sp_cpu_avg: Optional[float]
    sp_mem_avg_mb: Optional[float]
    app_login_duration_avg_ms: Optional[float]  # From Prometheus
    keycloak_cpu_total_s: Optional[float]  # From Prometheus
    keycloak_mem_peak_mb: Optional[float]  # From Prometheus
    notes: str


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    rows: List[RunRow] = []

    for run_dir in sorted(RAW_DIR.glob("*")):
        if not run_dir.is_dir():
            continue
        meta_path = run_dir / "run_metadata.json"
        k6_path = run_dir / "k6_summary.json"
        if not meta_path.exists() or not k6_path.exists():
            continue

        meta = read_json(meta_path)
        k6 = read_json(k6_path)

        profile = str(meta.get("profile") or meta.get("protocol") or "")
        scenario = str(meta.get("scenario") or "")
        rid = str(meta.get("run_id") or run_dir.name)
        repeat_no = safe_int(meta.get("repeat_no")) or 0
        concurrency = safe_int(meta.get("concurrency")) or 0
        warm_up_s = safe_int(meta.get("warm_up_s")) or 0
        duration_s = safe_int(meta.get("duration_s")) or 0
        seed = safe_int(meta.get("seed"))

        metric_base = "login_e2e_ms"
        if scenario == "session_reuse":
            metric_base = "session_reuse_ms"

        p50 = extract_k6_value(k6, metric_base, "med")  # k6 uses "med" for median (p50)
        p95 = extract_k6_value(k6, metric_base, "p(95)")
        p99 = extract_k6_value(k6, metric_base, "p(99)")

        throughput = extract_k6_value(k6, "http_reqs", "rate")
        err_rate = extract_k6_value(k6, "http_req_failed", "value")  # k6 uses "value" for http_req_failed
        redirect_avg = extract_k6_value(k6, "redirect_count", "avg")

        # Prefer Prometheus app-side token payload sizing when present.
        token_avg = None
        prom_sum_p = run_dir / "prometheus" / "range" / "sso_protocol_payload_size_bytes_sum.json"
        prom_count_p = run_dir / "prometheus" / "range" / "sso_protocol_payload_size_bytes_count.json"
        if prom_sum_p.exists() and prom_count_p.exists():
            prom_sum = read_json(prom_sum_p)
            prom_count = read_json(prom_count_p)
            ds, dc = prom_delta_sum_count(prom_sum, prom_count, {"service": "app", "profile": profile})
            if ds is not None and dc and dc > 0:
                token_avg = ds / dc

        # Fall back to a k6-side signal when an app-side metric is unavailable.
        if token_avg is None:
            token_avg = extract_k6_value(k6, "token_assertion_size_bytes", "avg")

        # Extract Prometheus app-side login duration
        # Note: This metric may be 0 if not updated during the run
        app_login_duration_avg_ms = None
        prom_dir = run_dir / "prometheus" / "range"
        login_sum_p = prom_dir / "sso_login_duration_seconds_sum.json"
        login_count_p = prom_dir / "sso_login_duration_seconds_count.json"
        if login_sum_p.exists() and login_count_p.exists():
            login_sum = read_json(login_sum_p)
            login_count = read_json(login_count_p)
            avg_seconds = prom_avg_from_sum_count(login_sum, login_count, {"service": "app", "profile": profile})
            # Only use if we have actual data (delta > 0)
            if avg_seconds is not None and avg_seconds > 0:
                app_login_duration_avg_ms = avg_seconds * 1000.0  # Convert to ms

        # Extract Keycloak CPU total (delta)
        # Note: This metric may not be available if Keycloak doesn't export it
        keycloak_cpu_total_s = None
        kc_cpu_p = prom_dir / "keycloak_process_cpu_seconds_total.json"
        if kc_cpu_p.exists():
            kc_cpu = read_json(kc_cpu_p)
            cpu_delta = prom_delta(kc_cpu, {"job": "keycloak"})
            # Only use if we have actual data (delta > 0)
            if cpu_delta is not None and cpu_delta > 0:
                keycloak_cpu_total_s = cpu_delta

        # Extract Keycloak memory peak (max across all heap areas)
        keycloak_mem_peak_mb = None
        kc_mem_p = prom_dir / "keycloak_jvm_memory_used_bytes.json"
        if kc_mem_p.exists():
            kc_mem = read_json(kc_mem_p)
            # Sum all heap areas for each timestamp, then take max
            data = kc_mem.get("data") or {}
            results = data.get("result") or []
            if results:
                # Group values by timestamp and sum heap areas
                timestamp_sums = {}
                for res in results:
                    metric = res.get("metric") or {}
                    if metric.get("job") == "keycloak" and metric.get("area") == "heap":
                        values = res.get("values") or []
                        for ts, val_str in values:
                            val = parse_float(val_str)
                            if val is not None:
                                if ts not in timestamp_sums:
                                    timestamp_sums[ts] = 0
                                timestamp_sums[ts] += val
                if timestamp_sums:
                    mem_max_bytes = max(timestamp_sums.values())
                    keycloak_mem_peak_mb = mem_max_bytes / (1024 * 1024)  # Convert bytes to MB

        docker_stats_path = run_dir / "docker_stats.jsonl"
        ds_avg = docker_stats_avg(docker_stats_path)
        keycloak = ds_avg.get("sso-keycloak") or {}
        keycloak_cpu = keycloak.get("cpu_perc_avg")
        keycloak_mem = keycloak.get("mem_used_mb_avg")

        app_container = "sso-app"
        app = ds_avg.get(app_container) or {}
        app_cpu = app.get("cpu_perc_avg")
        app_mem = app.get("mem_used_mb_avg")

        ts = meta.get("started_at") or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        rows.append(
            RunRow(
                run_id=rid,
                timestamp=str(ts),
                profile=profile,
                scenario=scenario,
                concurrency=concurrency,
                duration_s=duration_s,
                ramp_up_s=warm_up_s,
                repeat_no=repeat_no,
                seed=seed,
                login_p50_ms=p50,
                login_p95_ms=p95,
                login_p99_ms=p99,
                throughput_rps=throughput,
                error_rate=err_rate,
                redirect_count_avg=redirect_avg,
                token_size_avg_bytes=token_avg,
                keycloak_cpu_avg=keycloak_cpu,
                keycloak_mem_avg_mb=keycloak_mem,
                sp_cpu_avg=app_cpu,
                sp_mem_avg_mb=app_mem,
                app_login_duration_avg_ms=app_login_duration_avg_ms,
                keycloak_cpu_total_s=keycloak_cpu_total_s,
                keycloak_mem_peak_mb=keycloak_mem_peak_mb,
                notes="",
            )
        )

    out_csv = OUT_DIR / "runs.csv"
    with out_csv.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow([field.name for field in RunRow.__dataclass_fields__.values()])
        for r in rows:
            w.writerow([getattr(r, field.name) for field in RunRow.__dataclass_fields__.values()])

    # Optional Parquet output (requires pyarrow).
    out_parquet = OUT_DIR / "runs.parquet"
    try:
        import pandas as pd  # type: ignore

        df = pd.read_csv(out_csv)
        try:
            df.to_parquet(out_parquet, index=False)
        except Exception as e:
            print(f"Parquet export skipped (missing engine like pyarrow): {e}", file=sys.stderr)
    except Exception as e:
        print(f"Pandas not available; Parquet export skipped: {e}", file=sys.stderr)

    print(f"Wrote {len(rows)} runs to {out_csv}")
    if out_parquet.exists():
        print(f"Wrote Parquet to {out_parquet}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


