"""Safe local speed baseline using synthetic benign files only.

This is NOT a malware-detection accuracy benchmark. It benchmarks the existing
hash path, SQLite overhead and worker scheduling. No files outside a temporary
directory are read and no network calls or response actions are made.
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from tempfile import TemporaryDirectory

from app.config import ScanConfig
from core.scanner_manager import ScannerManager
from db.database import SQLiteStore
from engines.hash_engine import HashEngine


def run_benchmark(file_count: int, workers: int) -> dict:
    """Create benign fixtures, scan them, and report observed baseline speed."""
    if not 1 <= file_count <= 10000:
        raise ValueError("file_count debe estar entre 1 y 10000")
    if not 1 <= workers <= 16:
        raise ValueError("workers debe estar entre 1 y 16")
    with TemporaryDirectory(prefix="oneguard-benchmark-") as temp:
        root = Path(temp)
        targets = root / "samples"
        targets.mkdir()
        for index in range(file_count):
            # Use three typical sizes to avoid benchmarking only tiny files.
            size = (1024, 16 * 1024, 128 * 1024)[index % 3]
            content = (f"fixture-{index:06d}-".encode("ascii") * (size // 15 + 1))[:size]
            (targets / f"sample-{index:06d}.bin").write_bytes(content)
        store = SQLiteStore(root / "bench.db")
        config = ScanConfig(
            database_path=store.path, max_workers=workers,
            max_pending=max(workers * 4, 4),
        )
        scanner = ScannerManager(config, store, [HashEngine(store)])
        started = time.perf_counter()
        result = scanner.run([targets])
        duration = max(0.0, time.perf_counter() - started)
        metrics = store.get_engine_metrics(result.session_id)
        return {
            "benchmark": "synthetic-hash-only",
            "file_count": result.scanned_files,
            "worker_count": workers,
            "elapsed_seconds": round(duration, 3),
            "throughput_files_per_second": round(
                result.scanned_files / duration, 2
            ) if duration > 0 else None,
            "omitted_checks": result.omitted_checks,
            "errors": result.errors,
            "engine_metrics": metrics,
            "notes": (
                "Synthetic benign fixtures only; input sizes are not physical "
                "disk bytes read. Do not interpret as malware accuracy."
            ),
        }


def main() -> int:
    """Parse bounded CLI arguments and print a reusable JSON benchmark report."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--files", type=int, default=150)
    parser.add_argument("--workers", type=int, default=3)
    args = parser.parse_args()
    print(json.dumps(run_benchmark(args.files, args.workers),
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
