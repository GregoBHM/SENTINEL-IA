"""End-to-end Phase 4 coordinator test using a harmless local fixture."""
from pathlib import Path
from queue import Empty

from app.config import ScanConfig
from db.database import SQLiteStore
from ui.controller import ScanController
from ui.profiles import ScanPlan
from ui.repository import HistoryRepository


def test_gui_controller_runs_existing_core(tmp_path: Path) -> None:
    """Controller produces real persisted findings with its event queue."""
    fixture = tmp_path / "hello.txt"
    fixture.write_text("This is a safe synthetic fixture.", encoding="utf-8")
    db = tmp_path / "history.sqlite"
    store = SQLiteStore(db)
    from engines.hash_engine import HashEngine
    fingerprint = HashEngine(store).compute_hashes(fixture).sha256
    store.add_hash_signature(fingerprint, "Synthetic", "Fixture", "Test hash only", 85)
    config = ScanConfig(database_path=db, rule_directory=tmp_path / "emptyrules")
    controller = ScanController(config)
    controller.start(ScanPlan((fixture,), False, False, False, "custom"))
    assert controller._thread is not None
    controller._thread.join(timeout=12)
    assert not controller.running
    kinds = []
    while True:
        try:
            event = controller.bus.get_nowait()
        except Empty:
            break
        kinds.append(event.kind)
    assert "started" in kinds
    assert "finding" in kinds
    assert "complete" in kinds
    assert "investigation" in kinds
    assert "warning" in kinds  # missing YARA dependency or empty rule directory
    sessions = HistoryRepository(db).sessions()
    assert len(sessions) == 1
    assert len(HistoryRepository(db).findings(sessions[0].id)) == 1
    assert sessions[0].status == "completed"
