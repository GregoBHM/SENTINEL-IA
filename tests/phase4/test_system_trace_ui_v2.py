"""Qt regression: process-persistence evidence is selectable and non-causal."""
from __future__ import annotations

import os
from pathlib import Path

import pytest


def test_process_autorun_matches_have_trace_category(tmp_path: Path) -> None:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QApplication
    from core.system_identity import (
        SystemObservation, normalize_windows_executable, observe_autostart_reference,
    )
    from core.models import ScanTarget
    from db.database import SQLiteStore
    from ui.evidence_trace import EvidenceTraceDialog

    app = QApplication.instance() or QApplication([])
    store = SQLiteStore(tmp_path / "system-ui.db")
    store.start_session("synthetic")
    executable = r"C:\Synthetic\agent.exe"
    store.record_target_engine_runs(
        "synthetic", Path("process_23"), "scanned", [],
        system_observation=SystemObservation(
            target_path="process_23", kind="process", status="verified",
            pid=23, create_time=1000.0, executable_path=executable,
            normalized_executable=normalize_windows_executable(executable),
        ),
    )
    store.record_target_engine_runs(
        "synthetic", Path("persistence_0"), "scanned", [],
        system_observation=observe_autostart_reference(ScanTarget(
            Path("persistence_0"), "persistence", {
                "entry": r"HKCU\Software\Vendor\Start",
                "command": f'"{executable}" /background',
                "source_type": "registry",
            },
        )),
    )
    window = EvidenceTraceDialog(store, "synthetic")
    index = window.category.findData("system_link")
    assert index >= 0
    window.category.setCurrentIndex(index)
    assert window.table.rowCount() == 1
    assert "Ruta coincidente" in window.table.item(0, 2).text()
    assert "No demuestra" in window.table.item(0, 4).text()
    window.close()
    assert app is not None
