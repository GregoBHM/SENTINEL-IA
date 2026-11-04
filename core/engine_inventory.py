"""Explicit engine inventory for transparent, per-profile scan reporting.

'prepared' only means the engine was created; it does not certify that any
particular file was inspected. Invocation counts come from separate telemetry.
"""
from __future__ import annotations

from typing import Any, Iterable


_LABELS = (
    ("hash", "Firmas y hashes"),
    ("yara", "Reglas YARA"),
    ("pe_static", "Ejecutables PE"),
    ("script_static", "Scripts"),
    ("archive", "Comprimidos"),
)


def build_engine_inventory(
    engines: Iterable[Any], *, inspect_processes: bool,
    inspect_persistence: bool, online_authorized: bool,
    online_configured: bool, is_windows: bool,
    process_targets: int = 0, persistence_targets: int = 0,
) -> list[dict[str, str]]:
    """Report requested and available components without claiming full coverage."""
    present = {str(engine.name) for engine in engines}
    rows: list[dict[str, str]] = []
    for engine_id, title in _LABELS:
        available = engine_id in present
        rows.append({
            "id": engine_id, "title": title,
            "state": "prepared" if available else "unavailable",
            "note": (
                "Instanciado; la cobertura depende del tipo de objetivo."
                if available else
                "No se pudo preparar; revisar registro y configuración."
            ),
        })
    for engine_id, title, requested, targets in (
        ("process_network", "Procesos y red", inspect_processes, process_targets),
        ("persistence", "Persistencia Windows", inspect_persistence, persistence_targets),
    ):
        if not requested:
            status, note = "not_requested", "No fue autorizado en este análisis."
        elif not is_windows:
            status, note = "unavailable", "Requiere Windows."
        elif engine_id not in present:
            status, note = "unavailable", "El componente no pudo inicializarse."
        elif targets == 0:
            status, note = "partial", "No se obtuvo inventario verificable de objetivos."
        else:
            status, note = (
                "prepared", f"{targets} objetivos inventariados; pendientes de comprobación."
            )
        rows.append({"id": engine_id, "title": title, "state": status, "note": note})
    if not online_authorized:
        status, note = "not_requested", "No se autorizó la consulta externa."
    elif not online_configured:
        status, note = "unavailable", "Sin credenciales; se mantiene el análisis local."
    else:
        status, note = (
            "prepared",
            "Configurado dentro del motor de hashes; no garantiza disponibilidad de red.",
        )
    rows.append({
        "id": "reputation", "title": "Reputación externa",
        "state": status, "note": note,
    })
    return rows
