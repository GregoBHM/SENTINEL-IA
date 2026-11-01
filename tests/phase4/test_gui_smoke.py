"""Native Qt smoke checks (skipped where PySide6 is unavailable)."""
from __future__ import annotations

import os
from pathlib import Path

import pytest


def test_qt_window_opens_and_wizard_requires_consent(tmp_path: Path) -> None:
    """Create a real Qt window offscreen and check mandatory consent gating."""
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QApplication
    from app.config import ScanConfig
    from ui.window import OneGuardWindow
    from ui.wizard import ConsentWizard

    app = QApplication.instance() or QApplication([])
    main = OneGuardWindow(ScanConfig(database_path=tmp_path / "test.db"))
    assert main.pages.count() == 7
    assert main.scan_status.text() == "Sin análisis en curso"
    wizard = ConsentWizard(main)
    wizard.steps.setCurrentIndex(1)
    wizard._refresh()
    assert not wizard.forward.isEnabled()
    wizard.files.setChecked(True)
    assert wizard.forward.isEnabled()
    wizard.close()
    main.close()
    assert app is not None
