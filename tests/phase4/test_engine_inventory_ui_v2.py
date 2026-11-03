"""Qt regression for visible engine availability, independent of performance counts."""
from __future__ import annotations

import os
from pathlib import Path

import pytest


def test_engine_status_display_includes_unavailable_and_not_requested(
    tmp_path: Path,
) -> None:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QApplication
    from app.config import ScanConfig
    from core.models import ScanEvent
    from ui.window import OneGuardWindow

    app = QApplication.instance() or QApplication([])
    window = OneGuardWindow(ScanConfig(database_path=tmp_path / "inventory.db"))
    window._switch_page(1)
    window._prepare_live_scan()
    window._apply_event(ScanEvent("engine_inventory", {
        "engines": [
            {"id": "hash", "title": "Firmas y hashes",
             "state": "prepared", "note": "Preparado."},
            {"id": "yara", "title": "Reglas YARA",
             "state": "unavailable", "note": "Reglas no disponibles."},
            {"id": "process_network", "title": "Procesos",
             "state": "not_requested", "note": "No autorizado."},
        ],
    }))
    assert window.engine_perf_button.isEnabled()
    assert "1 preparados" in window.engine_status_label.text()
    assert "1 limitados" in window.engine_status_label.text()
    assert window._engine_inventory["process_network"]["state"] == "not_requested"
    window.close()
    assert app is not None
