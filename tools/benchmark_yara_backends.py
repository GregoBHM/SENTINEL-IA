"""Deterministic benign benchmark comparing classic YARA and optional YARA-X.

A compatibility check accompanies every timing sample. Never use this tiny
synthetic fixture set to claim improved real-world malware detection.
"""
from __future__ import annotations

import argparse
import json
from importlib.metadata import version
import statistics
import tempfile
import time
from pathlib import Path

from core.models import ScanTarget
from engines.yara_engine import YaraEngine
from engines.yara_x_engine import YaraXEngine


def run_benchmark(
    rule_directory: Path, *, file_count: int = 24, rounds: int = 3,
) -> dict:
    """Time both backends against identical harmless files and complete rules."""
    if not 1 <= file_count <= 500 or not 1 <= rounds <= 10:
        raise ValueError("Parámetros de benchmark fuera de límites")
    rule_directory = Path(rule_directory)
    compiled: dict[str, object] = {}
    compile_seconds: dict[str, float] = {}
    for name, engine_class in (("classic", YaraEngine), ("yarax", YaraXEngine)):
        started = time.perf_counter()
        compiled[name] = engine_class(rule_directory)
        compile_seconds[name] = round(time.perf_counter() - started, 5)

    corpus: list[tuple[str, bytes]] = []
    for index in range(file_count):
        # Fixed-size, non-executable and non-malicious synthetic files.
        size = (1024, 16 * 1024, 128 * 1024)[index % 3]
        marker = (
            b"ONEGUARD_SYNTHETIC_TEST_SIGNATURE"
            if index % 4 == 0 else b"ordinary harmless fixture"
        )
        content = (f"BENIGN-{index:04d}.".encode() * (size // 12 + 1))[:size]
        if marker.startswith(b"ONEGUARD"):
            content = content[:256] + marker + content[256 + len(marker):]
        corpus.append((f"fixture-{index:03d}.bin", content))

    runs: dict[str, list[float]] = {"classic": [], "yarax": []}
    signatures: dict[str, dict[str, tuple[str, ...]]] = {}
    with tempfile.TemporaryDirectory(prefix="oneguard-yara-eval-") as temp:
        root = Path(temp)
        paths = []
        for filename, data in corpus:
            path = root / filename
            path.write_bytes(data)
            paths.append(path)
        # Alternate execution order per round to reduce warmed-cache bias.
        for round_idx in range(rounds):
            order = (
                ("classic", "yarax") if round_idx % 2 == 0
                else ("yarax", "classic")
            )
            for backend in order:
                engine = compiled[backend]
                started = time.perf_counter()
                result = {}
                for path in paths:
                    findings = engine.scan(ScanTarget(path))
                    result[path.name] = tuple(sorted(
                        f.rule_id for f in findings
                    ))
                runs[backend].append(
                    time.perf_counter() - started
                )
                if backend not in signatures:
                    signatures[backend] = result
                elif signatures[backend] != result:
                    raise RuntimeError(
                        f"Resultados no deterministas en {backend}"
                    )
    disagreements = [
        name for name, _data in corpus
        if signatures["classic"][name] != signatures["yarax"][name]
    ]
    median_seconds = {
        name: round(statistics.median(samples), 5)
        for name, samples in runs.items()
    }
    return {
        "benchmark": "yara-vs-yarax-synthetic",
        "files": file_count,
        "rounds": rounds,
        "rules_folder": str(rule_directory),
        "rule_files": len(list(rule_directory.rglob("*.yar"))) +
                      len(list(rule_directory.rglob("*.yara"))),
        "backend_versions": {
            "classic": version("yara-python"),
            "yarax": version("yara-x"),
        },
        "compile_seconds": compile_seconds,
        "scan_seconds_median": median_seconds,
        "scan_seconds_samples": {
            k: [round(value, 5) for value in v] for k, v in runs.items()
        },
        "disagreement_count": len(disagreements),
        "disagreement_files": disagreements[:25],
        "interpretation": (
            "Only deterministic benign fixtures; matching parity is NOT "
            "real-world sensitivity, specificity, or malware detection accuracy. "
            "Timings vary with disk/CPU/cache and are not a controlled speedup claim."
        ),
    }


def main() -> int:
    """Print a machine-readable report and flag disagreements to CI."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules", type=Path, default=(
        Path(__file__).resolve().parents[1] / "rules" / "bundled"
    ))
    parser.add_argument("--files", type=int, default=24)
    parser.add_argument("--rounds", type=int, default=3)
    args = parser.parse_args()
    result = run_benchmark(
        args.rules, file_count=args.files, rounds=args.rounds
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if result["disagreement_count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
