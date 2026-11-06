"""Measure hash-I/O lane throughput on harmless synthetic files only.

Usage: python -m tools.benchmark_hash_io --files 40 --size-kib 128
The benchmark reports observations, not a guaranteed performance improvement.
"""
from __future__ import annotations

import argparse
import json
import tempfile
import time
from pathlib import Path

from app.config import ScanConfig
from core.scanner_manager import ScannerManager
from db.database import SQLiteStore
from engines.hash_engine import HashEngine


def evaluate(files: list[Path], database: Path, *, lanes: int) -> dict:
    store = SQLiteStore(database)
    config = ScanConfig(
        database_path=database, max_workers=4, max_pending=8,
        max_hash_io_workers=lanes,
    )
    manager = ScannerManager(config, store, [HashEngine(store)])
    started = time.perf_counter()
    summary = manager.run(files)
    elapsed = time.perf_counter() - started
    return {
        "hash_io_workers": lanes,
        "elapsed_seconds": round(elapsed, 4),
        "scanned_files": summary.scanned_files,
        "errors": summary.errors,
        "omitted_checks": summary.omitted_checks,
        "status": summary.status.value,
        "throughput_files_per_second": round(
            summary.scanned_files / elapsed if elapsed > 0 else 0, 2
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--files", type=int, default=40)
    parser.add_argument("--size-kib", type=int, default=128)
    args = parser.parse_args()
    if not (1 <= args.files <= 500 and 1 <= args.size_kib <= 4096):
        parser.error("File count or size outside bounded synthetic limits")

    with tempfile.TemporaryDirectory(prefix="oneguard-benchmark-") as directory:
        root = Path(directory)
        files = []
        # Only harmless byte patterns and no executable code are generated.
        payload = b"MZ" + b"synthetic-only-3d4\n" * (
            max(1, (args.size_kib * 1024 - 2) // len(b"synthetic-only-3d4\n"))
        )
        payload = payload[:args.size_kib * 1024]
        for index in range(args.files):
            file = root / f"harmless_{index}.exe"
            file.write_bytes(payload + bytes([index % 256]))
            files.append(file)
        records = [
            evaluate(files, root / f"benchmark_lanes_{lanes}.sqlite", lanes=lanes)
            for lanes in (1, 2, 4)
        ]
        print(json.dumps({
            "method": "synthetic_only, same files, sequential trials; filesystem cache may bias results",
            "records": records,
            "note": "Higher throughput is not proof of better malware detection",
        }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
