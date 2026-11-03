"""Focused GUI regressions for truthful scan lifecycle and result states."""
from __future__ import annotations

import os
from pathlib import Path

import pytest


def test_failed_bootstrap_keeps_scan_log_visible(tmp_path: Path) -> None:
    """A failed startup must not redirect the user to an empty results table."""
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QApplication
    from app.config import ScanConfig
    from ui.window import OneGuardWindow

    application = QApplication.instance() or QApplication([])
    window = OneGuardWindow(ScanConfig(database_path=tmp_path / "no-session.db"))
    window._switch_page(1)
    window._prepare_live_scan()
    window._complete({"status": "failed"})
    assert window.pages.currentIndex() == 1
    assert "fallido" in window.scan_status.text().lower()
    assert "Transcurrido" in window.elapsed_label.text()
    assert window.model.rowCount() == 0
    window.close()
    assert application is not None


def test_scan_presets_are_available_in_home(tmp_path: Path) -> None:
    """The home screen exposes mode selection without bypassing consent."""
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QApplication, QPushButton
    from app.config import ScanConfig
    from ui.window import OneGuardWindow

    application = QApplication.instance() or QApplication([])
    window = OneGuardWindow(ScanConfig(database_path=tmp_path / "test.db"))
    options = [
        item for item in window.pages.widget(0).findChildren(QPushButton)
        if item.text() == "Configurar análisis"
    ]
    assert len(options) == 3
    assert window.home_status is not None
    window.close()
    assert application is not None
