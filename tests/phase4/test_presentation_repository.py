"""Actual SQLite UI read models and evidence integrity tests."""
from pathlib import Path

from core.models import AggregatedFinding, Finding, ScanStatus, ScanSummary, Severity
from db.database import SQLiteStore
from ui.repository import HistoryRepository


def test_session_and_evidence_are_readable(tmp_path: Path) -> None:
    """The UI must show real persisted engine evidence instead of dummy rows."""
    database = tmp_path / "history.db"
    store = SQLiteStore(database)
    store.start_session("real-session")
    evidence = Finding(
        target=str(tmp_path / "synthetic.txt"), engine="unit-fixture", threat_type="Fixture",
        reason="Patrón sintético de prueba", severity=Severity.LOW,
        risk_score=24, confidence=44, details={"test_only": True},
    )
    verdict = AggregatedFinding(
        target=evidence.target, threat_type="Fixture", severity=Severity.LOW,
        risk_score=24, confidence=44, reason=evidence.reason,
        engines=(evidence.engine,), evidence=(evidence,),
    )
    store.save_finding("real-session", verdict)
    store.finish_session(ScanSummary("real-session", ScanStatus.COMPLETED, scanned_files=1,
                                    finding_files=1))
    reader = HistoryRepository(database)
    sessions = reader.sessions()
    assert sessions[0].status == "completed"
    findings = reader.findings("real-session")
    assert len(findings) == 1
    assert findings[0].reason == "Patrón sintético de prueba"
    observed = reader.evidence(findings[0].id)
    assert observed[0]["details"]["test_only"] is True
    assert reader.findings("different-session") == []
