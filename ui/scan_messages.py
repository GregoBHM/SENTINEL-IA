"""User-facing explanations for actual scanner initialization failures.

The original error remains in the activity log for technical diagnosis.
"""
from __future__ import annotations


def explain_scan_error(message: str) -> str:
    """Return an actionable explanation without assuming the device is infected."""
    normalized = str(message).casefold().replace("\\", "/")
    if "schema.sql" in normalized and (
        "filenotfounderror" in normalized or "no such file" in normalized
    ):
        return (
            "Falta la estructura SQLite dentro del ejecutable. "
            "Instala una compilación corregida de Sentinel OneGuard; "
            "no hace falta formatear ni reparar Windows."
        )
    if "permissionerror" in normalized or "access is denied" in normalized:
        return (
            "Windows denegó acceso a un recurso. Consulta el registro técnico "
            "y comprueba los permisos antes de repetir el análisis."
        )
    if "disk full" in normalized or "no space left" in normalized:
        return (
            "No hay espacio suficiente para almacenar el historial. "
            "Revisa el almacenamiento disponible y repite el análisis."
        )
    return (
        "No se completó la preparación o el análisis. "
        "Revisa el registro técnico, conserva el error y vuelve a intentarlo "
        "solo después de identificar la causa."
    )
