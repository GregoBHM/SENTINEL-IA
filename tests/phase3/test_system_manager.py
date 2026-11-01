"""Phase 3 system-target integration doesn't read nonexistent pseudo-files."""
from pathlib import Path

from app.config import ScanConfig
from core.detection_engine import DetectionEngine
from core.models import Finding, ScanTarget, Severity
from core.scanner_manager import ScannerManager
from db.database import SQLiteStore


class DummySystemEngine(DetectionEngine):
    """Harmless fake that inspects metadata, not live Windows processes."""
    name = "mock_system"

    def scan(self, target: ScanTarget) -> list[Finding]:
        """Create a finding only for an explicit synthetic process target."""
        if target.kind != "process":
            return []
        return [Finding(target=str(target.path), engine=self.name, threat_type="Fixture",
                        reason="Test", severity=Severity.LOW, risk_score=20, confidence=40)]


def test_scan_system_target_without_hashing(store: SQLiteStore) -> None:
    """A process pseudo-path must not be opened as a file or counted as one."""
    config = ScanConfig(database_path=store.path)
    manager = ScannerManager(config, store, [DummySystemEngine()])
    summary = manager.run([], [ScanTarget(Path("process_9999"), "process", {"pid": 9999})])
    assert summary.scanned_system_targets == 1
    assert summary.scanned_files == 0
    assert summary.finding_files == 1
    assert summary.errors == 0
