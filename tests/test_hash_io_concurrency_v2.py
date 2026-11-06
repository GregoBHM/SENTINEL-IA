"""Tests that bounded hashing does not run more reads than configured."""
from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from app.config import ScanConfig, load_config_file
from core.models import ScanStatus
from core.scanner_manager import ScannerManager
from db.database import SQLiteStore
from engines.hash_engine import HashEngine


def test_configuration_bounds_and_toml(tmp_path: Path):
    with pytest.raises(ValueError):
        ScanConfig(max_hash_io_workers=0)
    with pytest.raises(ValueError):
        ScanConfig(max_hash_io_workers=9)
    config_path = tmp_path / "options.toml"
    config_path.write_text(
        "[scanner]\nmax_workers = 4\nmax_pending = 4\n"
        "max_hash_io_workers = 1\n", encoding="utf-8",
    )
    parsed = load_config_file(config_path)
    assert parsed.max_hash_io_workers == 1
    assert parsed.max_workers == 4


def test_concurrent_pe_hash_observations_respect_one_slot(
    monkeypatch, tmp_path: Path,
):
    import core.scanner_manager as scanner

    files = []
    for n in range(8):
        path = tmp_path / f"synthetic_{n}.exe"
        path.write_bytes(b"MZ" + bytes([n]) * 4096)
        files.append(path)

    store = SQLiteStore(tmp_path / "scan.sqlite")
    manager = ScannerManager(
        ScanConfig(database_path=store.path, max_workers=4,
                   max_pending=8, max_hash_io_workers=1),
        store, [HashEngine(store)],
    )
    lock = threading.Lock()
    active = 0
    peak = 0
    original = scanner.observe_file_identity

    def observed(path):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.015)
            return original(path)
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(scanner, "observe_file_identity", observed)
    summary = manager.run(files)
    assert summary.status == ScanStatus.COMPLETED
    assert summary.scanned_files == len(files)
    assert summary.errors == 0
    assert peak == 1
    assert len(store.get_file_identities(summary.session_id)) == len(files)


def test_non_pe_hash_engine_uses_same_slot(monkeypatch, tmp_path: Path):
    files = []
    for n in range(6):
        path = tmp_path / f"synthetic_{n}.txt"
        path.write_bytes(b"harmless" + bytes([n]) * 1024)
        files.append(path)

    store = SQLiteStore(tmp_path / "scan.sqlite")
    engine = HashEngine(store)
    manager = ScannerManager(
        ScanConfig(database_path=store.path, max_workers=3,
                   max_pending=6, max_hash_io_workers=1),
        store, [engine],
    )
    lock = threading.Lock()
    peak, active = 0, 0
    original = engine.compute_hashes

    def monitored(path):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.01)
            return original(path)
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(engine, "compute_hashes", monitored)
    summary = manager.run(files)
    assert summary.status == ScanStatus.COMPLETED
    assert summary.errors == 0
    assert summary.scanned_files == len(files)
    assert peak == 1
