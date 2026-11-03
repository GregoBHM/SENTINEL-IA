"""Tests for honest, actionable scanner error explanations."""
from __future__ import annotations

from ui.scan_messages import explain_scan_error


def test_frozen_sqlite_schema_error_is_recognized() -> None:
    """Missing PyInstaller SQL files must not be described as malware."""
    message = (
        "Error al iniciar: FileNotFoundError: [Errno 2] No such file or "
        "directory: 'C:\\Users\\Demo\\AppData\\Local\\Temp\\_MEI123\\db\\schema.sql'"
    )
    explanation = explain_scan_error(message)
    assert "SQLite" in explanation
    assert "compilación corregida" in explanation
    assert "formatear" in explanation


def test_permission_and_generic_errors_preserve_uncertainty() -> None:
    """Avoid claiming the device is infected when a subsystem fails."""
    assert "denegó acceso" in explain_scan_error("PermissionError: denied")
    assert "Revisa el registro" in explain_scan_error("RuntimeError: desconocido")
