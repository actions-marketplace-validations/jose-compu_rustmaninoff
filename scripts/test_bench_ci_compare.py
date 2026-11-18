#!/usr/bin/env python3
"""Unit tests for benchmark comparison/report helpers."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
import sys

sys.path.insert(0, str(ROOT / "scripts"))
import bench_ci_compare as bench  # noqa: E402


class BenchCiCompareTests(unittest.TestCase):
    def test_pct_delta(self) -> None:
        self.assertAlmostEqual(bench.pct_delta(100.0, 115.0), 15.0)
        self.assertAlmostEqual(bench.pct_delta(50.0, 48.0), -4.0)

    def test_build_table_contains_marker(self) -> None:
        rows = [
            {
                "name": "Kubernetes",
                "baseline_median_ms": 10.0,
                "candidate_median_ms": 11.0,
                "candidate_min_ms": 10.0,
                "candidate_max_ms": 12.0,
                "delta_ms": 1.0,
                "delta_pct": 10.0,
                "candidate_peak_rss_kb": 1024,
            }
        ]
        table = bench.build_table(rows, title="Test", pr_label="PR")
        self.assertIn(bench.SUMMARY_MARKER, table)
        self.assertIn("Kubernetes", table)
        self.assertIn("10.0%", table)

    def test_thresholds_env_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "thresholds.json"
            path.write_text(json.dumps({"warn_pct": 5, "fail_pct": 15}))
            old = bench.THRESHOLDS_PATH
            bench.THRESHOLDS_PATH = path
            try:
                import os

                os.environ["BENCH_WARN_PCT"] = "7"
                os.environ["BENCH_FAIL_PCT"] = "20"
                warn, fail = bench.load_thresholds()
                self.assertEqual(warn, 7.0)
                self.assertEqual(fail, 20.0)
            finally:
                bench.THRESHOLDS_PATH = old
                os.environ.pop("BENCH_WARN_PCT", None)
                os.environ.pop("BENCH_FAIL_PCT", None)


if __name__ == "__main__":
    unittest.main()