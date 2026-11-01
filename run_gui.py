"""Launch the branded PySide6 interface, including frozen Windows builds."""
from __future__ import annotations

import json
import logging
import sys
import tempfile
from pathlib import Path

from core.logging_setup import configure_logging


def smoke_test(report_path: Path, application: object) -> int:
    """Exercise Qt initialization without inspecting real files or processes.

    This explicit validation mode is useful for CI before building the elevated
    binary. It never runs engines, opens the network or performs remediation.
    """
    from app.config import ScanConfig
    from db.database import SQLiteStore
    from ui.branding import logo_path, icon_path
    from ui.window import OneGuardWindow

    result = {"product": "Sentinel OneGuard", "qt": False,
              "window": False, "icon": False, "rules": False}
    with tempfile.TemporaryDirectory(prefix="oneguard-smoke-") as work:
        config = ScanConfig(database_path=Path(work) / "test.db")
        SQLiteStore(config.database_path)  # Check the SQL bootstrap used by real scans.
        result["icon"] = icon_path().is_file() and logo_path().is_file()
        result["rules"] = any(config.rule_directory.glob("*.yar"))
        result["qt"] = application is not None
        window = OneGuardWindow(config)
        result["window"] = window.pages.count() == 7
        window.close()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return 0 if all(result[key] for key in ("qt", "window", "icon", "rules")) else 1


def configure_taskbar_identity() -> None:
    """Give Windows a stable application identifier for correct icon grouping."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
            "Sentinel.OneGuard.Antimalware"
        )
    except (AttributeError, OSError):
        logging.getLogger("oneguard.ui").warning("No se pudo asignar AppUserModelID")


def main() -> int:
    """Create Qt once and keep its widgets on the main thread."""
    configure_logging()
    try:
        from PySide6.QtGui import QIcon
        from PySide6.QtWidgets import QApplication, QMessageBox
    except ImportError:
        logging.getLogger("oneguard").error(
            "PySide6 falta; instala: python -m pip install -r requirements-gui.txt")
        return 2

    from ui.branding import icon_path
    from ui.theme import STYLESHEET
    from ui.window import OneGuardWindow

    configure_taskbar_identity()
    application = QApplication(sys.argv)
    application.setApplicationName("Sentinel OneGuard")
    application.setOrganizationName("Sentinel OneGuard")
    application.setWindowIcon(QIcon(str(icon_path())))
    application.setStyle("Fusion")
    application.setStyleSheet(STYLESHEET)

    if "--smoke-test-file" in sys.argv:
        try:
            i = sys.argv.index("--smoke-test-file")
            return smoke_test(Path(sys.argv[i + 1]), application)
        except (IndexError, OSError, ValueError, RuntimeError) as exc:
            logging.getLogger("oneguard.ui").exception("Smoke test falló: %s", type(exc).__name__)
            return 3

    try:
        window = OneGuardWindow()
    except Exception as exc:
        logging.getLogger("oneguard.ui").exception("Fallo al iniciar la interfaz")
        QMessageBox.critical(None, "Sentinel OneGuard", 
                             f"No se pudo iniciar: {type(exc).__name__}")
        return 1
    window.show()
    return application.exec()


if __name__ == "__main__":
    raise SystemExit(main())
