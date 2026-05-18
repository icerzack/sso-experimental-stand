#!/usr/bin/env python3
"""
zitadel-benchmark.py — End-to-end Zitadel benchmark suite

Runs k6 load tests at multiple VU levels, captures Prometheus metrics
and Docker resource data, then produces a structured JSON report.

Usage:
    python3 scripts/zitadel-benchmark.py [--vu-levels 10,50,100] [--hold 60s]
"""
import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ── Configuration ──

BASE_DIR = Path(__file__).resolve().parent.parent
PROFILE_DIR = BASE_DIR / "load-tests" / "profiles" / "C_zitadel"
RESULTS_DIR = BASE_DIR / "results"
PROM_URL = os.environ.get("PROM_URL", "http://localhost:9090")
DOCKER_BIN = "/usr/local/bin/docker"

CONFIG_ENV = PROFILE_DIR / "config.env"
K6_SCRIPT = PROFILE_DIR / "oidc-login.js"

DEFAULT_VU_LEVELS = [10, 50, 100]
DEFAULT_HOLD = "60s"


def log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def run(cmd, **kwargs):
    """Run a command and return CompletedProcess."""
    return subprocess.run(cmd, capture_output=True, text=True, timeout=kwargs.pop("timeout", 30), **kwargs)


# ── Prometheus helpers ──

def prom_instant(query):
    """Run an instant PromQL query and return {label: value} dict."""
    r = run(["curl", "-sk", f"{PROM_URL}/api/v1/query", "--data-urlencode", f"query={query}"])
    try:
        d = json.loads(r.stdout)
        if d.get("status") != "success":
            return {}
        results = {}
        for item in d["data"]["result"]:
            labels = item["metric"]
            key = (labels.get("container_name") or labels.get("id", "?")).split("/")[-1][:20]
            results[key] = float(item["value"][1])
        return results
    except Exception:
        return {}


def prom_range(query, start_ts, end_ts, step="15s"):
    """Run a range PromQL query and return list of values."""
    r = run(["curl", "-sk",
             f"{PROM_URL}/api/v1/query_range",
             "--data-urlencode", f"query={query}",
             "--data-urlencode", f"start={start_ts}",
             "--data-urlencode", f"end={end_ts}",
             "--data-urlencode", f"step={step}"])
    try:
        d = json.loads(r.stdout)
        if d.get("status") != "success":
            return []
        values = []
        for item in d["data"]["result"]:
            for ts_val in item["values"]:
                values.append(float(ts_val[1]))
        return values
    except Exception:
        return []


# ── Docker resource collection ──

def docker_stats(container):
    """Get CPU% and memory from docker stats."""
    r = run([DOCKER_BIN, "stats", "--no-stream", "--format",
             "{{.CPUPerc}}|{{.MemUsage}}|{{.NetIO}}|{{.BlockIO}}", container])
    if r.returncode != 0 or "|" not in r.stdout:
        return {"cpu_pct": 0, "mem_mb": 0}
    parts = r.stdout.strip().split("|")
    cpu = float(parts[0].strip().replace("%", ""))
    mem_raw = parts[1].strip().split("/")[0].strip()
    # Parse memory like "121.3MiB"
    mem_mb = 0
    m = re.match(r'([\d.]+)\s*(GiB|MiB|KiB)', mem_raw)
    if m:
        val = float(m.group(1))
        unit = m.group(2)
        if unit == "GiB":
            mem_mb = val * 1024
        elif unit == "MiB":
            mem_mb = val
        elif unit == "KiB":
            mem_mb = val / 1024
    return {"cpu_pct": cpu, "mem_mb": round(mem_mb, 1)}


class ResourceCollector:
    """Background Docker stats collector that runs during a load test."""

    def __init__(self, container_name, interval=3):
        self.container = container_name
        self.interval = interval
        self.samples = []
        self._process = None
        self._stop = False
        self._pid = None

    def start(self):
        import threading
        self._stop = False

        def _collect():
            while not self._stop:
                stats = docker_stats(self.container)
                stats["timestamp"] = time.time()
                self.samples.append(stats)
                time.sleep(self.interval)

        t = threading.Thread(target=_collect, daemon=True)
        t.start()

    def stop(self):
        self._stop = True
        time.sleep(0.5)

    def summary(self):
        if not self.samples:
            return {"avg_cpu": 0, "peak_cpu": 0, "avg_mem_mb": 0, "peak_mem_mb": 0, "samples": 0}

        cpus = [s["cpu_pct"] for s in self.samples]
        mems = [s["mem_mb"] for s in self.samples]

        return {
            "avg_cpu_pct": round(sum(cpus) / len(cpus), 1),
            "peak_cpu_pct": round(max(cpus), 1),
            "avg_mem_mb": round(sum(mems) / len(mems), 0),
            "peak_mem_mb": round(max(mems), 0),
            "min_mem_mb": round(min(mems), 0),
            "samples": len(self.samples),
        }


# ── Load config.env ──

def load_config():
    config = {}
    with open(CONFIG_ENV) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                config[key] = value
    return config


# ── Parse k6 JSON output ──

def parse_k6_results(json_path):
    latencies = []
    errors_total = 0
    errors_value_1 = 0
    iterations = 0
    http_reqs = []

    with open(json_path) as f:
        for line in f:
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            metric = entry.get("metric", "")
            point = entry.get("data", {})

            if metric == "login_latency" and "value" in point:
                latencies.append(float(point["value"]))
            elif metric == "errors":
                errors_total += 1
                if int(point.get("value", 0)) == 1:
                    errors_value_1 += 1
            elif metric == "iterations":
                iterations += 1
            elif metric == "http_req_duration" and "value" in point:
                http_reqs.append(float(point["value"]))

    result = {"iterations": iterations, "total_errors": errors_total, "error_count": errors_value_1}

    if latencies:
        latencies.sort()
        n = len(latencies)
        result.update({
            "login_count": n,
            "avg_ms": round(sum(latencies) / n),
            "min_ms": round(latencies[0]),
            "max_ms": round(latencies[-1]),
            "p50_ms": round(latencies[int(n * 0.50)]),
            "p90_ms": round(latencies[int(n * 0.90)]),
            "p95_ms": round(latencies[int(n * 0.95)]),
            "p99_ms": round(latencies[min(int(n * 0.99), n - 1)]),
            "error_rate_pct": round(errors_value_1 / max(n, 1) * 100, 1),
        })

    if http_reqs:
        http_reqs.sort()
        n = len(http_reqs)
        result["http_req_count"] = n
        result["http_req_p50_ms"] = round(http_reqs[int(n * 0.50)])
        result["http_req_p95_ms"] = round(http_reqs[int(n * 0.95)])

    return result


# ── Main benchmark runner ──

def main():
    parser = argparse.ArgumentParser(description="Zitadel OIDC Benchmark Suite")
    parser.add_argument("--vu-levels", default="10,50,100", help="Comma-separated VU levels")
    parser.add_argument("--hold", default="60s", help="Hold duration per stage")
    parser.add_argument("--skip-startup-test", action="store_true", help="Skip cold start measurement")
    args = parser.parse_args()

    vu_levels = [int(x) for x in args.vu_levels.split(",")]
    hold = args.hold

    config = load_config()

    log("=" * 60)
    log("  Zitadel OIDC Authorization Code Flow Benchmark")
    log(f"  VU levels: {vu_levels}")
    log(f"  Hold: {hold}")
    log(f"  Target: {config.get('BASE_URL', '?')}")
    log(f"  Client: {config.get('CLIENT_ID', '?')[:20]}...")
    log("=" * 60)

    # Verify prerequisites
    if not CONFIG_ENV.exists():
        log(f"FATAL: config.env not found at {CONFIG_ENV}")
        sys.exit(1)

    if not K6_SCRIPT.exists():
        log(f"FATAL: oidc-login.js not found at {K6_SCRIPT}")
        sys.exit(1)

    # Find k6 binary
    k6_candidates = [
        os.environ.get("K6_BIN", ""),
        "/opt/homebrew/bin/k6",
        "/usr/local/bin/k6",
        str(Path.home() / ".k6/bin/k6"),
    ]
    k6_bin = None
    for c in k6_candidates:
        if c and Path(c).is_file():
            k6_bin = c
            break
    if not k6_bin:
        # Try which
        r = run(["which", "k6"])
        if r.returncode == 0 and r.stdout.strip():
            k6_bin = r.stdout.strip()

    if not k6_bin:
        log("FATAL: k6 not found! Install: https://k6.io/docs/get-started/installation/")
        sys.exit(1)

    log(f"k6 found at: {k6_bin}")

    # Check connectivity
    idp_url = config.get("BASE_URL", "https://idp.sso-lab.local")
    r = run(["curl", "-sk", "-o/dev/null", "-w%{http_code}", f"{idp_url}/.well-known/openid-configuration"])
    if r.stdout.strip() != "200":
        log(f"FATAL: IdP not reachable at {idp_url} (HTTP {r.stdout.strip()})")
        sys.exit(1)
    log("IdP connectivity OK")

    # Prepare output directory
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_dir = RESULTS_DIR / "raw" / f"zitadel-{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=True)

    all_results = {
        "metadata": {
            "idp": "zitadel",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "system": {
                "cpu_cores": os.cpu_count() or 8,
                "platform": subprocess.run(["uname", "-ms"], capture_output=True, text=True).stdout.strip(),
            },
            "test_config": {
                "vu_levels": vu_levels,
                "hold_duration": hold,
                "base_url": config.get("BASE_URL"),
                "client_id": config.get("CLIENT_ID"),
                "test_user": config.get("TEST_USER"),
            },
        },
        "baseline": {},
        "stages": [],
    }

    # ── Capture baseline resources ──
    log("")
    log("Capturing idle resource baseline...")
    container = config.get("CONTAINER_NAME", "sso-lab-idp")
    idle_stats = docker_stats(container)

    # Get all container stats
    container_stats = {}
    r = run([DOCKER_BIN, "ps", "--filter", "name=sso-lab", "--format", "{{.Names}}"])
    for name in r.stdout.strip().split("\n"):
        name = name.strip()
        if name:
            s = docker_stats(name)
            container_stats[name] = s

    # Also get total resource counts via Traefik
    traefik_metrics = prom_instant('traefik_service_request_duration_seconds_count{service=~"idp.*"}')

    all_results["baseline"] = {
        "idle_idp_resources": idle_stats,
        "all_containers": container_stats,
        "traefik_request_counts": traefik_metrics,
    }

    log(f"  IdP idle: CPU={idle_stats['cpu_pct']}%, RAM={idle_stats['mem_mb']}MB")

    # ── Run benchmarks at each VU level ──

    for vu in vu_levels:
        log("")
        log(f"{'='*50}")
        log(f"  Starting benchmark: {vu} VU × {hold}")
        log(f"{'='*50}")

        k6_output = output_dir / f"k6-{vu}vu.json"
        resource_csv = output_dir / f"resources-{vu}vu.csv"

        # Start background resource collection
        res_collector = ResourceCollector(container, interval=3)
        test_start_time = time.time()
        prom_start = str(int(test_start_time))

        res_collector.start()

        # Build k6 command
        cmd = [
            k6_bin, "run",
            "-e", f"BASE_URL={config.get('BASE_URL', '')}",
            "-e", f"APP_URL={config.get('APP_URL', '')}",
            "-e", f"CLIENT_ID={config.get('CLIENT_ID', '')}",
            "-e", f"CLIENT_SECRET={config.get('CLIENT_SECRET', '')}",
            "-e", f"TEST_USER={config.get('TEST_USER', '')}",
            "-e", f"TEST_PASSWORD={config.get('TEST_PASSWORD', '')}",
            "-e", f"TARGET_VU={vu}",
            "-e", f"HOLD_DURATION={hold}",
            "--out", f"json={k6_output}",
            str(K6_SCRIPT),
        ]

        log(f"  Running: {' '.join(cmd[:6])}...")

        # Run k6
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

        test_end_time = time.time()
        prom_end = str(int(test_end_time))

        res_collector.stop()
        resource_summary = res_collector.summary()

        # Save raw k6 stdout/stderr
        with open(output_dir / f"k6-{vu}vu-stdout.txt", "w") as f:
            f.write(proc.stdout or "")
        with open(output_dir / f"k6-{vu}vu-stderr.txt", "w") as f:
            f.write(proc.stderr or "")

        # Parse k6 JSON output
        k6_results = parse_k6_results(k6_output) if k6_output.exists() else {}

        # Query Prometheus range data for this test window
        prom_data = {}
        prom_queries = {
            "idp_cpu": 'rate(container_cpu_usage_seconds_total{container_name="sso-lab-idp"}[30s]) * 100',
            "idp_memory": 'container_memory_working_set_bytes{container_name="sso-lab-idp"} / 1024 / 1024',
            "traefik_rps": 'rate(traefik_service_requests_total{service=~"idp.*"}[30s])',
            "postgres_conns": 'pg_stat_activity_count' if False else '',  # Only if pg exporter present
        }

        for name, query in prom_queries.items():
            if not query:
                continue
            values = prom_range(query, prom_start, prom_end)
            if values:
                prom_data[name] = {
                    "avg": round(sum(values) / len(values), 2),
                    "max": round(max(values), 2),
                    "min": round(min(values), 2),
                }

        # Stage result
        stage_result = {
            "vu_level": vu,
            "hold_duration": hold,
            "wall_clock_s": round(test_end_time - test_start_time, 1),
            "k6_exit_code": proc.returncode,
            "latency": {k: v for k, v in k6_results.items()},
            "resources": resource_summary,
            "prometheus": prom_data,
        }

        all_results["stages"].append(stage_result)

        # Print stage summary
        lat = k6_results
        log(f"  Results:")
        if lat.get("login_count"):
            log(f"    Logins:      {lat['login_count']}")
            log(f"    P50 latency: {lat.get('p50_ms','?')} ms")
            log(f"    P95 latency: {lat.get('p95_ms','?')} ms")
            log(f"    P99 latency: {lat.get('p99_ms','?')} ms")
            log(f"    Avg latency: {lat.get('avg_ms','?')} ms")
            log(f"    Error rate:  {lat.get('error_rate_pct','?')}%")
        else:
            log(f"    No login data collected!")
        log(f"    Peak CPU:    {resource_summary.get('peak_cpu_pct','?')}%")
        log(f"    Peak RAM:    {resource_summary.get('peak_mem_mb','?')} MB")

        # Cool-down between stages
        cool_down = max(10, vu // 10)
        log(f"  Cooling down for {cool_down}s...")
        time.sleep(cool_down)

    # ── Startup/recovery test ──

    if not args.skip_startup_test:
        log("")
        log("Measuring startup/recovery times...")

        # Cold start: stop → start → wait healthy
        run([DOCKER_BIN, "stop", container], timeout=30)
        time.sleep(3)

        t0 = time.time()
        run([DOCKER_BIN, "start", container], timeout=15)
        startup_waited = 0
        while startup_waited < 120:
            r = run([DOCKER_BIN, "inspect", "--format={{.State.Health.Status}}", container], timeout=10)
            if "healthy" in r.stdout:
                break
            time.sleep(2)
            startup_waited += 2

        startup_time = round(time.time() - t0, 1)
        log(f"  Cold startup time: {startup_time}s")

        # Recovery after kill
        run([DOCKER_BIN, "kill", container], timeout=15)
        time.sleep(2)

        t0 = time.time()
        run([DOCKER_BIN, "restart", container], timeout=15)
        recovery_waited = 0
        while recovery_waited < 120:
            r = run([DOCKER_BIN, "inspect", "--format={{.State.Health.Status}}", container], timeout=10)
            if "healthy" in r.stdout:
                break
            time.sleep(2)
            recovery_waited += 2

        recovery_time = round(time.time() - t0, 1)
        log(f"  Recovery after kill: {recovery_time}s")

        all_results["startup_recovery"] = {
            "cold_start_s": startup_time,
            "recovery_after_kill_s": recovery_time,
        }

        # Wait for stable before finishing
        time.sleep(10)

    # ── Post-test resource snapshot ──

    post_stats = docker_stats(container)
    all_results["post_test"] = {
        "idp_resources": post_stats,
    }

    # ── Write final report ──

    report_path = output_dir / "report.json"
    with open(report_path, "w") as f:
        json.dump(all_results, f, indent=2)

    # Also write a human-readable Markdown summary
    md_path = output_dir / "RESULTS_Zitadel.md"
    with open(md_path, "w") as f:
        f.write("# Profile E2C — Zitadel OIDC Benchmark Results\n\n")
        f.write("## Methodology\n\n")
        f.write("- **Platform**: macOS + Docker Desktop (ARM64)\n")
        f.write(f"- **CPU cores**: {os.cpu_count() or '?'}\n")
        f.write("- **IdP**: Zitadel (Go, cloud-native)\n")
        f.write("- **DB**: PostgreSQL 16-alpine\n")
        f.write("- **Reverse proxy**: Traefik v3.3 (TLS termination)\n")
        f.write("- **Load tool**: k6\n")
        f.write("- **Protocol**: OIDC Authorization Code Flow (6 steps: authorize → username → password → MFA skip → redirect → token exchange)\n")
        f.write(f"- **Test user**: {config.get('TEST_USER', '?')}\n")
        f.write("- **Note**: Zitadel does NOT support ROPC grant; only browser/Auth Code flow is available.\n\n")
        f.write("---\n\n")

        f.write("## Login Latency Summary\n\n")
        f.write("| VU | P50 (ms) | P95 (ms) | P99 (ms) | Avg (ms) | Errors (%) |\n")
        f.write("|----|----------|----------|----------|---------|------------|\n")

        for stage in all_results["stages"]:
            l = stage["latency"]
            vu = stage["vu_level"]
            p50 = l.get("p50_ms", "N/A")
            p95 = l.get("p95_ms", "N/A")
            p99 = l.get("p99_ms", "N/A")
            avg = l.get("avg_ms", "N/A")
            err = l.get("error_rate_pct", "N/A")
            f.write(f"| {vu} | {p50} | {p95} | {p99} | {avg} | {err} |\n")

        f.write("\n## Resource Usage\n\n")
        f.write("| Metric | Value |\n")
        f.write("|--------|------|\n")

        idle_mem = all_results["baseline"]["idle_idp_resources"].get("mem_mb", "?")
        f.write(f"| Idle RAM (MB) | {idle_mem} |\n")

        for stage in all_results["stages"]:
            r = stage["resources"]
            vu = stage["vu_level"]
            f.write(f"| RAM @ {vu}VU avg (MB) | {r.get('avg_mem_mb', '?')} |\n")
            f.write(f"| RAM @ {vu}VU peak (MB) | {r.get('peak_mem_mb', '?')} |\n")
            f.write(f"| CPU @ {vu}VU peak (%) | {r.get('peak_cpu_pct', '?')} |\n")

        if "startup_recovery" in all_results:
            sr = all_results["startup_recovery"]
            f.write(f"\n## Startup & Recovery\n\n")
            f.write(f"| Metric | Value |\n")
            f.write(f"|--------|------|\n")
            f.write(f"| Cold start (s) | {sr.get('cold_start_s', '?')} |\n")
            f.write(f"| Recovery after kill (s) | {sr.get('recovery_after_kill_s', '?')} |\n")

    # Print final summary
    log("")
    log("=" * 60)
    log("  BENCHMARK COMPLETE")
    log(f"  Report saved to: {output_dir}/")
    log(f"    - report.json    (structured data)")
    log(f"    - RESULTS_Zitadel.md   (human-readable)")
    log("=" * 60)

    # Quick comparison table on console
    print("\n╔═══════════════════════════════════════════════════════════════╗")
    print("║              ZITADEL BENCHMARK SUMMARY                      ║")
    print("╠═══════╦══════════╦══════════╦══════════╦═════════╦══════════╣")
    print("║  VU   ║  P50(ms) ║  P95(ms) ║  P99(ms) ║ Err(%)  ║ Peak RAM ║")
    print("╠═══════╬══════════╬══════════╬══════════╬═════════╬══════════╣")

    for stage in all_results["stages"]:
        l = stage["latency"]
        r = stage["resources"]
        vu = stage["vu_level"]
        p50 = l.get("p50_ms", "?")
        p95 = l.get("p95_ms", "?")
        p99 = l.get("p99_ms", "?")
        err = l.get("error_rate_pct", "?")
        ram = r.get("peak_mem_mb", "?")
        print(f"║ {vu:>4}  ║ {p50:>8} ║ {p95:>8} ║ {p99:>8} ║ {err:>7} ║ {ram:>5} MB  ║")

    print("╚═══════╩══════════╩══════════╩══════════╩═════════╩══════════╝")


if __name__ == "__main__":
    main()
