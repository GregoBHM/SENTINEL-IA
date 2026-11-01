"""Cancellation must not be lost across worker preparation and manager startup."""
from pathlib import Path

from app.config import ScanConfig
from core.models import ScanStatus
from core.scanner_manager import ScannerManager
from db.database import SQLiteStore
from engines.hash_engine import HashEngine


def test_cancel_before_run_is_respected(tmp_path: Path) -> None:
    """A cancellation before worker startup does not turn into a completed scan."""
    sample = tmp_path / "fixture.txt"
    sample.write_text("harmless")
    store = SQLiteStore(tmp_path / "test.sqlite")
    manager = ScannerManager(ScanConfig(database_path=store.path), store, [HashEngine(store)])
    manager.cancel()
    summary = manager.run([sample])
    assert summary.status == ScanStatus.CANCELLED
    assert summary.scanned_files == 0
