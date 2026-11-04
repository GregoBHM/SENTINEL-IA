"""Native Qt smoke test for real metrics and honest ETA scope."""
from __future__ import annotations

import os
from pathlib import Path

import pytest


def test_scan_metrics_render_known_only_without_claiming_global_eta(
    tmp_path: Path,
) -> None:
    """The GUI distinguishes an estimate for discovered work from total time."""
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PySide6")
    from PySide6.QtWidgets import QApplication
    from app.config import ScanConfig
    from ui.window import OneGuardWindow

    app = QApplication.instance() or QApplication([])
    window = OneGuardWindow(ScanConfig(database_path=tmp_path / "perf.db"))
    window._switch_page(1)
    window._prepare_live_scan()
    payload = {
        "engines": {
            "synthetic": {
                "checks": 10, "completed": 10, "skipped": 0, "errors": 0,
                "duration_seconds": 4.0, "input_size_bytes": 12345,
            },
        },
        "throughput_targets_per_second": 3.25,
        "eta": {
            "scope": "known", "seconds": 20,
            "low_seconds": 12, "high_seconds": 36,
        },
        "paused": False,
        "discovery_complete": False,
        "remaining_known": 12,
        "process_resources": {"cpu_percent": 12.5, "rss_bytes": 96 * 1024**2},
    }
    window._render_performance(payload)
    assert "Cola conocida" in window.eta_label.text()
    assert "se descubren" in window.eta_label.text()
    assert window.engine_perf_button.isEnabled()
    assert "CPU 12.5%" in window.resources_label.text()
    assert "96 MiB" in window.resources_label.text()
    assert "12" in window.pending_label.text()

    window._complete({
        "status": "completed", "scanned": 0, "errors": 0,
        "performance": {**payload, "eta": None, "discovery_complete": True},
    })
    assert "finalizado" in window.eta_label.text()
    window.close()
    assert app is not None
