"""Visual layout regressions for the desktop dashboard.

Qt-specific portions are skipped without native PySide6. No scan is started.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest


def test_qss_does_not_paint_opaque_label_bands() -> None:
    """The outer window owns background paint; labels remain transparent."""
    from ui.theme import STYLESHEET

    assert "QLabel { background: transparent;" in STYLESHEET
    assert "QWidget { background:" not in STYLESHEET
    assert "QWidget#PageSurface" in STYLESHEET


@pytest.mark.parametrize("width,height", [(1050, 680), (1390, 900)])
def test_sidebar_labels_fit_and_scan_is_scrollable(
    tmp_path: Path, width: int, height: int
) -> None:
    """Sidebar headings stay inside bounds at supported window sizes."""
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PySide6")

    from PySide6.QtWidgets import QApplication, QLabel, QScrollArea
    from app.config import ScanConfig
    from ui.theme import STYLESHEET
    from ui.window import OneGuardWindow

    app = QApplication.instance() or QApplication([])
    app.setStyle("Fusion")
    app.setStyleSheet(STYLESHEET)
    window = OneGuardWindow(ScanConfig(database_path=tmp_path / "test.db"))
    window.resize(width, height)
    window.show()
    app.processEvents()

    sidebar = window.nav_buttons[0].parentWidget()
    assert sidebar.width() >= 230
    headings = [
        child for child in sidebar.findChildren(QLabel)
        if child.text() in {
            "CENTRO DE ANÁLISIS",
            "ESTADO DEL EQUIPO",
            "MITIGACIÓN MANUAL",
        }
    ]
    assert len(headings) == 3
    for heading in headings:
        assert heading.width() >= heading.fontMetrics().horizontalAdvance(heading.text())
        assert heading.height() >= heading.fontMetrics().height()

    assert isinstance(window.pages.widget(1), QScrollArea)
    assert window.console.maximumHeight() < 260
    assert not window.failure_hint.isVisible()
    window.close()
