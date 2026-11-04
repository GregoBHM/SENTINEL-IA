"""Qt smoke test for the read-only investigation relationship panel."""
from __future__ import annotations

import os
from pathlib import Path

import pytest


def test_trace_dialog_shows_provenance_and_local_filter(tmp_path: Path) -> None:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QApplication
    from core.archive_members import ArchiveMemberCoverage
    from core.performance import EngineTiming
    from db.database import SQLiteStore
    from ui.evidence_trace import EvidenceTraceDialog

    app = QApplication.instance() or QApplication([])
    store = SQLiteStore(tmp_path / "ui-trace.db")
    store.start_session("fixture")
    path = Path("C:/Synthetic/benign.zip")
    store.record_target_engine_runs(
        "fixture", path, "partial",
        [EngineTiming("archive", "success", 0.1, 20)],
        archive_members=[
            ArchiveMemberCoverage(str(path), "zip", "partial"),
            ArchiveMemberCoverage(
                str(path) + "::internal.txt", "file",
                "uninspected", reason="Límite", depth=2,
            ),
        ],
    )
    store.record_coverage(
        "fixture", path, "archive", "SCAN.ARCHIVE.PARTIAL", {},
        "No inspeccionado",
    )
    dialog = EvidenceTraceDialog(store, "fixture")
    assert dialog.table.rowCount() >= 2
    archive_index = dialog.category.findData("archive")
    dialog.category.setCurrentIndex(archive_index)
    assert dialog.table.rowCount() == 1
    assert "Contiene entrada enumerada" in dialog.table.item(0, 2).text()
    dialog.close()
    assert app is not None
