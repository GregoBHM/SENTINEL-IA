"""Capture deterministic Qt layouts for Windows CI visual review.

Uses a disposable SQLite database and a synthetic failure event; it does not
read user files, invoke scan engines, access the network, or modify Windows.
"""
from __future__ import annotations

import os
from pathlib import Path
from tempfile import TemporaryDirectory


def main() -> int:
    """Save startup, scanning, failed-scan and compact-window screenshots."""
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    from PySide6.QtWidgets import QApplication
    from app.config import ScanConfig
    from core.models import ScanEvent
    from ui.theme import STYLESHEET
    from ui.window import OneGuardWindow

    output = Path("artifacts/gui-previews")
    output.mkdir(parents=True, exist_ok=True)
    app = QApplication.instance() or QApplication([])
    app.setStyle("Fusion")
    app.setStyleSheet(STYLESHEET)

    def capture(window: OneGuardWindow, name: str) -> None:
        """Render one current source-code UI frame without scanning any file."""
        app.processEvents()
        screenshot = window.grab()
        if screenshot.isNull() or not screenshot.save(str(output / name), "PNG"):
            raise RuntimeError(f"No se pudo guardar captura: {name}")

    with TemporaryDirectory(prefix="oneguard-preview-") as work:
        window = OneGuardWindow(ScanConfig(database_path=Path(work) / "preview.db"))
        window.resize(1390, 900)
        window.show()
        capture(window, "01-inicio-1390.png")

        window._switch_page(1)
        window._prepare_live_scan()
        capture(window, "02-analisis-1390.png")

        # Synthetic UI event only; not a real incident or file inspection.
        window._apply_event(ScanEvent(
            "error", {"message": "FileNotFoundError: No such file: db/schema.sql"}
        ))
        window._complete({"status": "failed", "scanned": 0, "errors": 1})
        capture(window, "03-fallo-explicado-1390.png")
        window.resize(1050, 680)
        capture(window, "04-fallo-compacto-1050.png")
        window.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
