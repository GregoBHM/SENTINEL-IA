"""Safe benchmark catches match disagreements without claiming accuracy."""
from __future__ import annotations

from pathlib import Path

import pytest

from tools.benchmark_yara_backends import run_benchmark


def test_benchmark_rejects_unbounded_runs() -> None:
    """Never write an unlimited number of test files."""
    with pytest.raises(ValueError):
        run_benchmark(Path("does-not-exist"), file_count=10000)


def test_bundled_rule_parity_on_synthetic_corpus() -> None:
    """An optional second YARA engine must agree on known benign fixtures."""
    pytest.importorskip("yara")
    pytest.importorskip("yara_x")
    rules = Path(__file__).parents[1] / "rules" / "bundled"
    result = run_benchmark(rules, file_count=12, rounds=2)
    assert result["disagreement_count"] == 0
    assert result["files"] == 12
    assert result["scan_seconds_median"]["classic"] >= 0
    assert result["scan_seconds_median"]["yarax"] >= 0
