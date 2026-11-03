"""Qt presentation regression tests for v2 customer messages."""
from __future__ import annotations

import os
from pathlib import Path

import pytest


def test_nontechnical_notices_do_not_inflate_coverage(tmp_path: Path) -> None:
    """Three YARA omissions are not four malware warnings when API keys are absent."""
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QApplication
    from app.config import ScanConfig
    from core.events import make_event
    from ui.window import OneGuardWindow

    app = QApplication.instance() or QApplication([])
    window = OneGuardWindow(ScanConfig(database_path=tmp_path / "v2.db"))
    window._switch_page(1)
    window._prepare_live_scan()
    window._apply_event(make_event(
        "warning", "SCAN.REPUTATION.UNCONFIGURED", engine="reputation",
    ))
    assert window.partial_tile.number.text() == "0"
    for index in range(3):
        window._apply_event(make_event(
            "skipped", "SCAN.YARA.SIZE_LIMIT", engine="yara",
            path=f"synthetic-{index}.bin",
            params={"limit_bytes": 64 * 1024**2, "size_bytes": 90 * 1024**2},
        ))
    assert window._seen_warnings == 3
    assert window.coverage_detail_button.isEnabled()
    assert window.console.toPlainText().count("YARA no revisó") == 1
    window.close()
    assert app is not None
