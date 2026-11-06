"""Qt/offscreen regression for session summaries and honest findings overview."""
from __future__ import annotations

import os
from pathlib import Path

import pytest


def test_home_and_findings_use_persisted_counts(tmp_path: Path) -> None:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QApplication
    from app.config import ScanConfig
    from core.models import ScanStatus, ScanSummary
    from db.database import SQLiteStore
    from ui.repository import FindingRow
    from ui.window import OneGuardWindow

    app = QApplication.instance() or QApplication([])
    path = tmp_path / "ui4.sqlite"
    store = SQLiteStore(path)
    store.start_session("local-synthetic")
    store.finish_session(ScanSummary(
        session_id="local-synthetic", status=ScanStatus.COMPLETED,
        scanned_files=12, finding_files=2, errors=1,
    ))
    window = OneGuardWindow(ScanConfig(database_path=path))
    window.refresh_history()
    assert window.home_scanned_tile.number.text() == "12"
    assert window.home_findings_tile.number.text() == "2"
    assert window.home_errors_tile.number.text() == "1"
    assert "equipo limpio" in window.home_coverage_warning.text()

    rows = [
        FindingRow(
            id=1, session_id="local-synthetic", target="fixture.ps1",
            threat_type="Test only", severity="high", score=70,
            confidence=50, reason="Synthetic fixture", engines=("script_static",),
            sha256=None, suppressed=False, timestamp="2026-01-01T00:00:00",
        ),
        FindingRow(
            id=2, session_id="local-synthetic", target="fixture.exe",
            threat_type="Test only", severity="low", score=30,
            confidence=30, reason="Synthetic fixture", engines=("hash",),
            sha256=None, suppressed=True, timestamp="2026-01-01T00:00:00",
        ),
    ]
    window._show_rows(rows)
    summary = window.results_review_label.text()
    assert "1 alertas altas/críticas" in summary
    assert "1 excluidas" in summary
    assert "filas cargadas" in summary
    window.close()
    assert app is not None


def test_home_initial_state_is_unknown(tmp_path: Path) -> None:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QApplication
    from app.config import ScanConfig
    from ui.window import OneGuardWindow

    app = QApplication.instance() or QApplication([])
    window = OneGuardWindow(ScanConfig(database_path=tmp_path / "empty.sqlite"))
    assert window.home_scanned_tile.number.text() == "—"
    assert "Sin evaluación previa" in window.home_coverage_warning.text()
    window.close()
    assert app is not None
