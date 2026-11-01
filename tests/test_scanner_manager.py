"""End-to-end Phase 2 integration through the hash engine and SQLite."""
from pathlib import Path

from app.config import ScanConfig
from core.models import ScanStatus
from core.scanner_manager import ScannerManager, discover_files
from db.database import SQLiteStore
from engines.hash_engine import HashEngine


def test_directory_scan_detects_signature(store: SQLiteStore, tmp_path: Path) -> None:
    """Run the scan, collect a detection and persist a completed session."""
    root = tmp_path / "samples"
    root.mkdir()
    sample = root / "test.bin"
    sample.write_bytes(b"harmless test")
    engine = HashEngine(store)
    digest = engine.compute_hashes(sample).sha256
    store.add_hash_signature(digest, "unit-marker", "Synthetic", "Reviewed fixture", 95)
    config = ScanConfig(database_path=store.path, max_workers=2, max_pending=2)
    manager = ScannerManager(config, store, [engine])
    summary = manager.run([root])
    assert summary.status == ScanStatus.COMPLETED
    assert summary.scanned_files == 1
    assert summary.finding_files == 1
    assert summary.findings[0].risk_score == 95
    with store.connection() as conn:
        assert conn.execute("SELECT COUNT(*) AS n FROM findings").fetchone()["n"] == 1
        assert conn.execute("SELECT COUNT(*) AS n FROM evidence").fetchone()["n"] == 1


def test_discovery_does_not_follow_symlinks(tmp_path: Path) -> None:
    """Never follow a symlink to outside the selected directory."""
    root = tmp_path / "scan"
    root.mkdir()
    (root / "ok.txt").write_text("safe")
    outside = tmp_path / "outside.txt"
    outside.write_text("not in scope")
    try:
        (root / "link.txt").symlink_to(outside)
    except OSError:
        return  # Windows without symlink developer privilege.
    found = list(discover_files([root]))
    assert root / "ok.txt" in found
    assert root / "link.txt" not in found


def test_scan_empty_folder_is_complete(store: SQLiteStore, tmp_path: Path) -> None:
    """A legitimate empty scope is not an error or a fabricated detection."""
    root = tmp_path / "empty"
    root.mkdir()
    cfg = ScanConfig(database_path=store.path)
    summary = ScannerManager(cfg, store, [HashEngine(store)]).run([root])
    assert summary.status == ScanStatus.COMPLETED
    assert summary.finding_files == 0
