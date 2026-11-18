#!/usr/bin/env python3
"""Compare rustmaninoff CLI benches between a baseline binary and a candidate on fixed corpora."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
THRESHOLDS_PATH = ROOT / "benchmarks" / "regression_thresholds.json"
PINS_DIR = ROOT / "benchmarks" / "pins"
SUMMARY_MARKER = "<!-- rustmaninoff-bench-regression -->"


@dataclass(frozen=True)
class Scenario:
    name: str
    argv: tuple[str, ...]


def load_thresholds() -> tuple[float, float]:
    data = json.loads(THRESHOLDS_PATH.read_text())
    warn = float(os.environ.get("BENCH_WARN_PCT", data.get("warn_pct", 5)))
    fail = float(os.environ.get("BENCH_FAIL_PCT", data.get("fail_pct", 15)))
    return warn, fail


def load_runs() -> int:
    return max(1, int(os.environ.get("BENCH_RUNS", "3")))


def median(values: list[float]) -> float:
    if not values:
        return 0.0
    return float(statistics.median(values))


def ensure_pinned_terraform() -> Path:
    pin = json.loads((PINS_DIR / "terraform-aws-s3-bucket.json").read_text())
    cache = ROOT / "benchmarks" / ".cache" / "terraform-aws-s3-bucket"
    if (cache / ".git").is_dir():
        return cache
    cache.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "git",
            "clone",
            "--quiet",
            "--depth",
            "1",
            "--branch",
            str(pin["ref"]),
            str(pin["url"]),
            str(cache),
        ],
        check=True,
    )
    return cache


def build_scenarios() -> list[Scenario]:
    corpus = ROOT / "benchmarks" / "corpus"
    plan = ROOT / "testdata" / "terraform-plan" / "sensitive_matrix.tfplan.json"
    tf_large = ensure_pinned_terraform()
    common = ("--soft-fail", "--compact")
    return [
        Scenario("Terraform (large pin)", ("scan", str(tf_large), "--framework", "terraform", *common)),
        Scenario("Kubernetes", ("scan", str(corpus / "kubernetes"), "--framework", "kubernetes", *common)),
        Scenario(
            "CloudFormation",
            ("scan", str(corpus / "cloudformation"), "--framework", "cloudformation", *common),
        ),
        Scenario("Dockerfiles", ("scan", str(corpus / "docker"), "--framework", "docker", *common)),
        Scenario(
            "Terraform plan JSON",
            (
                "scan",
                str(plan),
                "--framework",
                "terraform_plan",
                *common,
            ),
        ),
    ]


def run_once(bin_path: Path, argv: tuple[str, ...]) -> tuple[float, int | None]:
    cmd = [str(bin_path), *argv]
    rss_kb: int | None = None
    time_bin = shutil.which("/usr/bin/time")
    start = time.perf_counter()
    if time_bin and os.path.exists(time_bin):
        proc = subprocess.run(
            [time_bin, "-v", *cmd],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=False,
        )
        end = time.perf_counter()
        if proc.stderr:
            m = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", proc.stderr.decode())
            if m:
                rss_kb = int(m.group(1))
    else:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        end = time.perf_counter()
    return (end - start) * 1000.0, rss_kb


def bench_scenario(bin_path: Path, scenario: Scenario, runs: int) -> dict[str, Any]:
    warmup_argv = scenario.argv
    run_once(bin_path, warmup_argv)
    times: list[float] = []
    rss_values: list[int] = []
    for _ in range(runs):
        ms, rss = run_once(bin_path, scenario.argv)
        times.append(ms)
        if rss is not None:
            rss_values.append(rss)
    return {
        "median_ms": median(times),
        "min_ms": min(times),
        "max_ms": max(times),
        "samples_ms": times,
        "peak_rss_kb": max(rss_values) if rss_values else None,
    }


def pct_delta(baseline: float, candidate: float) -> float:
    if baseline <= 0:
        return 0.0
    return ((candidate - baseline) / baseline) * 100.0


def fmt_ms(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:.0f} ms"


def fmt_delta(abs_ms: float, pct: float) -> tuple[str, str]:
    sign = "+" if abs_ms >= 0 else ""
    return f"{sign}{abs_ms:.0f} ms", f"{sign}{pct:.1f}%"


def build_table(rows: list[dict[str, Any]], *, title: str, pr_label: str) -> str:
    lines = [
        SUMMARY_MARKER,
        f"## {title}",
        "",
        "| Scenario | Baseline (main) | "
        f"{pr_label} | Spread (min–max) | Delta | Delta % | Peak memory |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in rows:
        spread = f"{row['candidate_min_ms']:.0f}–{row['candidate_max_ms']:.0f} ms"
        d_abs, d_pct = fmt_delta(row["delta_ms"], row["delta_pct"])
        peak = (
            f"{row['candidate_peak_rss_kb']:.0f} KiB"
            if row.get("candidate_peak_rss_kb") is not None
            else ""
        )
        lines.append(
            "| {name} | {base} | {cand} | {spread} | {d} | {dp} | {peak} |".format(
                name=row["name"],
                base=fmt_ms(row["baseline_median_ms"]),
                cand=fmt_ms(row["candidate_median_ms"]),
                spread=spread,
                d=d_abs,
                dp=d_pct,
                peak=peak,
            )
        )
    return "\n".join(lines) + "\n"


def compare(
    baseline_bin: Path,
    candidate_bin: Path,
    runs: int,
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    warn_pct, fail_pct = load_thresholds()
    rows: list[dict[str, Any]] = []
    warnings: list[str] = []
    failures: list[str] = []
    for scenario in build_scenarios():
        base = bench_scenario(baseline_bin, scenario, runs)
        cand = bench_scenario(candidate_bin, scenario, runs)
        delta_ms = cand["median_ms"] - base["median_ms"]
        delta_pct = pct_delta(base["median_ms"], cand["median_ms"])
        row = {
            "name": scenario.name,
            "baseline_median_ms": base["median_ms"],
            "candidate_median_ms": cand["median_ms"],
            "baseline_min_ms": base["min_ms"],
            "baseline_max_ms": base["max_ms"],
            "candidate_min_ms": cand["min_ms"],
            "candidate_max_ms": cand["max_ms"],
            "baseline_peak_rss_kb": base["peak_rss_kb"],
            "candidate_peak_rss_kb": cand["peak_rss_kb"],
            "delta_ms": delta_ms,
            "delta_pct": delta_pct,
        }
        rows.append(row)
        if delta_pct > fail_pct:
            failures.append(f"{scenario.name}: median {delta_pct:.1f}% slower than baseline")
        elif delta_pct > warn_pct:
            warnings.append(f"{scenario.name}: median {delta_pct:.1f}% slower than baseline")
    return rows, warnings, failures


def record_main(candidate_bin: Path, runs: int, commit: str) -> dict[str, Any]:
    data: dict[str, Any] = {"commit": commit, "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    scenarios: list[dict[str, Any]] = []
    for scenario in build_scenarios():
        cand = bench_scenario(candidate_bin, scenario, runs)
        scenarios.append(
            {
                "name": scenario.name,
                "median_ms": cand["median_ms"],
                "min_ms": cand["min_ms"],
                "max_ms": cand["max_ms"],
                "peak_rss_kb": cand["peak_rss_kb"],
            }
        )
    data["scenarios"] = scenarios
    return data


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline-bin", type=Path)
    parser.add_argument("--candidate-bin", type=Path, required=True)
    parser.add_argument("--summary-out", type=Path)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--markdown-out", type=Path)
    parser.add_argument("--record-main", action="store_true")
    parser.add_argument("--commit", default="")
    parser.add_argument("--pr-label", default="This pull request")
    args = parser.parse_args()
    runs = load_runs()

    if args.record_main:
        payload = record_main(args.candidate_bin, runs, args.commit or "main")
        if args.json_out:
            args.json_out.write_text(json.dumps(payload, indent=2) + "\n")
        if args.summary_out:
            lines = [
                "## Benchmark baseline recorded",
                "",
                f"Commit `{payload['commit']}` medians stored for trend tracking.",
            ]
            lines.append("")
            lines.append("| Scenario | Median | Spread | Peak memory |")
            lines.append("| --- | ---: | ---: | ---: |")
            for item in payload["scenarios"]:
                spread = f"{item['min_ms']:.0f}–{item['max_ms']:.0f} ms"
                peak = (
                    f"{item['peak_rss_kb']:.0f} KiB" if item.get("peak_rss_kb") is not None else ""
                )
                lines.append(
                    f"| {item['name']} | {item['median_ms']:.0f} ms | {spread} | {peak} |"
                )
            args.summary_out.write_text("\n".join(lines) + "\n")
        print(json.dumps(payload, indent=2))
        return 0

    if not args.baseline_bin:
        print("--baseline-bin is required unless --record-main", file=sys.stderr)
        return 2

    rows, warnings, failures = compare(args.baseline_bin, args.candidate_bin, runs)
    table = build_table(rows, title="Benchmark regression vs main", pr_label=args.pr_label)

    payload = {
        "rows": rows,
        "warnings": warnings,
        "failures": failures,
        "warn_pct": load_thresholds()[0],
        "fail_pct": load_thresholds()[1],
    }
    if args.json_out:
        args.json_out.write_text(json.dumps(payload, indent=2) + "\n")
    if args.markdown_out:
        args.markdown_out.write_text(table)
    if args.summary_out:
        body = table
        if warnings:
            body += "\n**Warnings (slower than {:.0f}%):**\n".format(load_thresholds()[0])
            for item in warnings:
                body += f"- {item}\n"
        if failures:
            body += "\n**Failures (slower than {:.0f}%):**\n".format(load_thresholds()[1])
            for item in failures:
                body += f"- {item}\n"
        if not shutil.which("/usr/bin/time"):
            body += "\n_Peak memory unavailable on this runner (`/usr/bin/time -v` missing)._ \n"
        args.summary_out.write_text(body)

    print(table)
    if warnings:
        print("\nWarnings:", *warnings, sep="\n- ")
    if failures:
        print("\nFailures:", *failures, sep="\n- ")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())