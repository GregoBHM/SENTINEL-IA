"""Control methods should not block or alter user files."""
from pathlib import Path

from app.config import ScanConfig
from core.scanner_manager import ScannerManager
from db.database import SQLiteStore
from engines.hash_engine import HashEngine


def test_pause_resume_cancel_flags(store: SQLiteStore) -> None:
    """Pause and cancel signal workers without deleting or changing files."""
    manager = ScannerManager(ScanConfig(database_path=store.path), store, [HashEngine(store)])
    manager.pause()
    assert not manager._resume.is_set()
    manager.resume()
    assert manager._resume.is_set()
    manager.cancel()
    assert manager._cancel.is_set()
    assert manager._resume.is_set()


def test_discovery_errors_are_counted(store: SQLiteStore, tmp_path: Path) -> None:
    """An inaccessible or missing scan root must not be counted as clean."""
    missing = tmp_path / "not-existing"
    cfg = ScanConfig(database_path=store.path)
    summary = ScannerManager(cfg, store, [HashEngine(store)]).run([missing])
    assert summary.errors == 1
    assert summary.scanned_files == 0
