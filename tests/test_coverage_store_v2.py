"""Real SQLite and scanner tests for omitted-engine coverage."""
from __future__ import annotations

import sqlite3
from pathlib import Path

from app.config import ScanConfig
from core.detection_engine import DetectionEngine
from core.errors import ScanSkipped
from core.models import Finding, ScanTarget, ScanStatus
from core.scanner_manager import ScannerManager
from db.database import SQLiteStore
from engines.hash_engine import HashEngine


class ControlledOmission(DetectionEngine):
    """Synthetic engine representing an intentional YARA-size omission."""

    name = "synthetic-coverage"

    def scan(self, target: ScanTarget) -> list[Finding]:
        """Produce no malware findings, only a structured skip."""
        raise ScanSkipped(
            "synthetic size limitation", code="SCAN.YARA.SIZE_LIMIT",
            params={"size_bytes": 100 * 1024**2, "limit_bytes": 64 * 1024**2},
        )


def test_omission_does_not_increase_threats_or_errors(tmp_path: Path) -> None:
    """Keep independent counts and retain the exact affected path in SQLite."""
    store = SQLiteStore(tmp_path / "oneguard.db")
    root = tmp_path / "sample"
    root.mkdir()
    target = root / "safe.bin"
    target.write_bytes(b"inert fixture")
    cfg = ScanConfig(database_path=store.path, max_workers=1, max_pending=1)
    scanner = ScannerManager(cfg, store, [HashEngine(store), ControlledOmission()])
    result = scanner.run([root])
    assert result.status is ScanStatus.COMPLETED
    assert result.omitted_checks == 1
    assert result.errors == 0
    assert result.finding_files == 0
    with store.connection() as conn:
        row = conn.execute(
            "SELECT omitted_checks, errors, finding_files FROM scan_sessions"
        ).fetchone()
        coverage = conn.execute(
            "SELECT target_path, engine, event_code, params_json "
            "FROM scan_coverage"
        ).fetchone()
    assert tuple(row) == (1, 0, 0)
    assert coverage["target_path"] == str(target)
    assert coverage["engine"] == "synthetic-coverage"
    assert coverage["event_code"] == "SCAN.YARA.SIZE_LIMIT"
    assert '"limit_bytes": 67108864' in coverage["params_json"]


def test_existing_scan_db_is_migrated_without_losing_history(tmp_path: Path) -> None:
    """Old scan_sessions tables get the new counter additively."""
    database = tmp_path / "legacy.db"
    with sqlite3.connect(database) as conn:
        conn.execute(
            "CREATE TABLE scan_sessions ("
            "id TEXT PRIMARY KEY, started_at TEXT NOT NULL, finished_at TEXT, "
            "status TEXT NOT NULL, discovered_files INTEGER NOT NULL DEFAULT 0, "
            "scanned_files INTEGER NOT NULL DEFAULT 0, "
            "finding_files INTEGER NOT NULL DEFAULT 0, "
            "errors INTEGER NOT NULL DEFAULT 0)"
        )
        conn.execute(
            "INSERT INTO scan_sessions(id,started_at,status) "
            "VALUES('old','2026-11-01T00:00:00','completed')"
        )
    store = SQLiteStore(database)
    with store.connection() as conn:
        row = conn.execute(
            "SELECT id, omitted_checks FROM scan_sessions WHERE id='old'"
        ).fetchone()
    assert tuple(row) == ("old", 0)
