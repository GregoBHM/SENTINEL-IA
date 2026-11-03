"""Scanner integration: times, final payload and SQLite persistence."""
from __future__ import annotations

from pathlib import Path
from queue import Empty

from app.config import ScanConfig
from core.detection_engine import DetectionEngine
from core.event_bus import EventBus
from core.models import Finding, ScanStatus, ScanTarget
from core.scanner_manager import ScannerManager
from db.database import SQLiteStore


class HarmlessEngine(DetectionEngine):
    """Synthetic scanner with no malware content or network calls."""

    name = "synthetic-perf"

    def scan(self, target: ScanTarget) -> list[Finding]:
        """Report a completed invocation with zero findings."""
        return []


def test_metrics_are_saved_and_final_event_contains_snapshot(tmp_path: Path) -> None:
    """Persist aggregate timing without adding per-file data to the engine table."""
    root = tmp_path / "files"
    root.mkdir()
    (root / "one.txt").write_bytes(b"hello")
    (root / "two.bin").write_bytes(b"abc")
    db = SQLiteStore(tmp_path / "history.db")
    cfg = ScanConfig(database_path=db.path, max_workers=1, max_pending=2)
    bus = EventBus()
    manager = ScannerManager(cfg, db, [HarmlessEngine()], bus)
    summary = manager.run([root])

    assert summary.status == ScanStatus.COMPLETED
    assert summary.scanned_files == 2
    assert summary.finding_files == 0
    assert summary.engine_metrics["synthetic-perf"]["checks"] == 2
    rows = db.get_engine_metrics(summary.session_id)
    assert len(rows) == 1
    assert rows[0]["engine"] == "synthetic-perf"
    assert rows[0]["checks"] == 2
    assert rows[0]["completed"] == 2
    assert rows[0]["input_size_bytes"] == 8

    events = []
    while True:
        try:
            events.append(bus.get_nowait())
        except Empty:
            break
    final = next(item for item in events if item.kind == "complete")
    performance = final.payload["performance"]
    assert performance["completed_targets"] == 2
    assert performance["known_targets"] == 2
    assert performance["discovery_complete"]
    assert performance["eta"] is None
    assert performance["engines"]["synthetic-perf"]["checks"] == 2


def test_historical_database_preserves_schema_and_metrics(tmp_path: Path) -> None:
    """An existing database can be re-opened with the additive performance table."""
    db = SQLiteStore(tmp_path / "existing.db")
    db.start_session("historic")
    db.save_engine_metrics("historic", {
        "hash": {
            "checks": 7, "completed": 6, "skipped": 1, "errors": 0,
            "duration_seconds": 1.25, "input_size_bytes": 50,
        }
    })
    again = SQLiteStore(db.path)
    saved = again.get_engine_metrics("historic")
    assert saved[0]["duration_seconds"] == 1.25
    assert saved[0]["skipped"] == 1
