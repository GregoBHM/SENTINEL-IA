"""Offscreen Qt regression for content identity and honest coverage review."""
from __future__ import annotations

import os
from pathlib import Path

import pytest


def test_evidence_dialog_exposes_content_identity_and_omissions(tmp_path: Path):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QApplication
    from core.file_identity import FileIdentity
    from core.performance import EngineTiming
    from db.database import SQLiteStore
    from ui.evidence_trace import EvidenceTraceDialog

    app = QApplication.instance() or QApplication([])
    store = SQLiteStore(tmp_path / "dialog.sqlite")
    store.start_session("case")
    observed_path = tmp_path / "synthetic.exe"
    store.record_target_engine_runs(
        "case", observed_path, "scanned",
        [EngineTiming("hash", "success", 0.02, 64)],
        file_identity=FileIdentity(
            str(observed_path), "observed", sha256="b" * 64,
            file_size=64, bytes_read=64,
        ),
    )
    dialog = EvidenceTraceDialog(store, "case")
    assert "Comprobaciones finalizadas: 1" in dialog.coverage_label.text()
    assert "NO" in dialog.coverage_label.text() or "No" in dialog.coverage_label.text()
    index = dialog.category.findData("content_identity")
    assert index >= 0
    dialog.category.setCurrentIndex(index)
    assert dialog.table.rowCount() == 1
    assert "Huella de contenido" in dialog.table.item(0, 2).text()
    assert "no confirma seguridad" in dialog.table.item(0, 4).text()
    dialog.close()
    assert app is not None
