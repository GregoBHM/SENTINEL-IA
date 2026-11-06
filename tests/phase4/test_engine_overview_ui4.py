"""UI 4.0 synthetic regressions: live engine inventory and coverage truth."""
from __future__ import annotations

import os

import pytest


def _qt():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


def test_overview_keeps_prepared_separate_from_completed():
    app = _qt()
    from ui.engine_overview import EngineOverview, engine_rows

    inventory = {
        "hash": {"title": "Firmas y hashes", "state": "prepared", "note": "Available"},
        "yara": {"title": "Reglas YARA", "state": "unavailable", "note": "No rules"},
        "process_network": {
            "title": "Procesos y red", "state": "not_requested", "note": "No consent",
        },
    }
    metrics = {"hash": {"checks": 3, "completed": 2, "skipped": 1,
                        "errors": 0, "signals": 0}}
    rows = engine_rows(inventory, metrics)
    assert rows[0]["status"] == "Con omisiones"
    assert rows[0]["completed"] == 2
    assert rows[1]["status"] == "No disponible"
    assert rows[2]["status"] == "No solicitado"
    panel = EngineOverview()
    panel.update_snapshot(inventory, metrics)
    assert panel.table.rowCount() == 3
    assert panel.table.item(0, 3).text() == "2"
    assert panel.table.item(1, 1).text() == "No disponible"
    assert "Preparado no equivale" in panel.caveat.text()
    panel.reset()
    assert panel.table.rowCount() == 0
    panel.close()
    assert app is not None


def test_overview_does_not_invent_success_for_prepared_engine():
    app = _qt()
    from ui.engine_overview import EngineOverview
    panel = EngineOverview()
    panel.update_snapshot(
        {"pe_static": {"title": "Ejecutables PE", "state": "prepared"}},
        {},
    )
    assert panel.table.item(0, 1).text() == "Preparado"
    assert panel.table.item(0, 3).text() == "—"
    assert "0 comprobaciones" in panel.summary.text()
    panel.close()
    assert app is not None


def test_main_window_updates_and_clears_live_engine_overview(tmp_path):
    app = _qt()
    from app.config import ScanConfig
    from ui.window import OneGuardWindow

    window = OneGuardWindow(ScanConfig(database_path=tmp_path / "ui.db"))
    window._render_engine_inventory([
        {"id": "hash", "title": "Firmas y hashes", "state": "prepared",
         "note": "local fixture"},
        {"id": "archive", "title": "Comprimidos", "state": "partial",
         "note": "synthetic limited"},
    ])
    window._render_performance({
        "engines": {"hash": {"checks": 5, "completed": 4, "skipped": 1,
                              "errors": 0, "signals": 1}},
        "remaining_known": 0,
        "discovery_complete": False,
    })
    assert window.engine_overview.table.rowCount() == 2
    assert window.engine_overview.table.item(0, 1).text() == "Con omisiones"
    assert window.engine_overview.table.item(0, 5).text() == "1"
    assert window.engine_overview.table.item(1, 1).text() == "Inventario parcial"
    window._prepare_live_scan()
    assert window.engine_overview.table.rowCount() == 0
    window.close()
    assert app is not None
