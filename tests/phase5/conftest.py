"""Safe synthetic findings with real file digests and a temporary SQLite DB."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from core.models import AggregatedFinding, Finding, ScanSummary, ScanStatus, Severity
from db.database import SQLiteStore


@pytest.fixture
def sample(tmp_path: Path):
    """Create an innocuous fixture, matching scan record and persisted finding."""
    root = tmp_path / "user"
    root.mkdir()
    file = root / "sample_script.txt"
    file.write_bytes(b"SENTINEL_ONEGUARD_SAFE_TEST_SAMPLE\n")
    digest = hashlib.sha256(file.read_bytes()).hexdigest()
    store = SQLiteStore(tmp_path / "store" / "database.sqlite")
    store.start_session("test-session")
    store.record_target("test-session", file, "scanned", digest)
    signal = Finding(str(file), "hash", "Prueba inocua", "Firma sintética de laboratorio",
                     Severity.HIGH, 72, 95, sha256=digest)
    verdict = AggregatedFinding(str(file), "Prueba inocua", Severity.HIGH,
                                72, 95, "Firma sintética", ("hash",), (signal,), sha256=digest)
    store.save_finding("test-session", verdict)
    store.finish_session(ScanSummary("test-session", ScanStatus.COMPLETED, 1, 1, 0, 1, 0))
    with store.connection() as conn:
        finding_id = conn.execute("SELECT id FROM findings").fetchone()[0]
    return store, file, digest, finding_id, tmp_path / "vault"
