"""Read-only Qt per-target coverage table regression."""
from __future__ import annotations

import os
from pathlib import Path

import pytest


def test_local_detail_displays_real_per_engine_states(tmp_path: Path) -> None:
    """GUI displays completed and inapplicable without claiming either is clean."""
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QApplication
    from core.performance import EngineTiming
    from db.database import SQLiteStore
    from ui.file_coverage import FileCoverageDialog

    app = QApplication.instance() or QApplication([])
    store = SQLiteStore(tmp_path / "coverage.db")
    store.start_session("sample")
    path = Path("C:/Synthetic/harmless.bin")
    store.record_target_engine_runs("sample", path, "scanned", [
        EngineTiming("hash", "success", 0.21, 300),
        EngineTiming("pe_static", "not_applicable", 0, 0),
        EngineTiming("yara", "skipped", 0.05, 300, reason="Límite"),
    ])
    window = FileCoverageDialog(store, "sample")
    assert window.table.rowCount() == 3
    result_labels = [
        window.table.item(i, 1).text() for i in range(window.table.rowCount())
    ]
    assert "No corresponde" in result_labels
    assert "Comprobación finalizada" in result_labels
    assert "Omitido · cobertura parcial" in result_labels
    window.selector.setEditText("C:/Unseen/no-such-file.bin")
    window.populate_for_path()
    assert window.table.rowCount() == 0
    assert "no equivale" in window.status.text().lower()
    window.close()
    assert app is not None
