"""Versioned scan-event contract and customer-friendly Spanish message catalog.

The event code, not a translated sentence, is the stable storage/API key.
Raw technical errors remain available locally for diagnosis.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from core.models import ScanEvent


@dataclass(frozen=True, slots=True)
class ClientMessage:
    """A safe, localized projection of a technical scan event."""

    code: str
    category: str
    level: str
    title: str
    description: str
    action: str | None
    dedupe_key: str


_CATALOG: dict[str, tuple[str, str, str, str | None]] = {
    "SCAN.REPUTATION.UNCONFIGURED": (
        "information", "INFO", "Reputación en línea no configurada",
        "Configurar proveedores",
    ),
    "SCAN.YARA.SIZE_LIMIT": (
        "coverage", "WARN", "YARA no revisó un archivo grande",
        "Ver archivos omitidos",
    ),
    "SCAN.YARA.UNAVAILABLE": (
        "coverage", "WARN", "Motor YARA no disponible",
        "Revisar configuración de YARA",
    ),
    "SCAN.ENGINE.SKIPPED": (
        "coverage", "WARN", "Un motor omitió un objetivo",
        "Ver cobertura",
    ),
    "SCAN.ENGINE.UNAVAILABLE": (
        "coverage", "WARN", "Cobertura parcial del sistema",
        "Ver cobertura",
    ),
    "SCAN.ENGINE.ERROR": (
        "error", "ERROR", "No se pudo analizar un objetivo",
        "Ver detalle técnico",
    ),
    "SCAN.INIT.FAILED": (
        "error", "ERROR", "No se pudo iniciar el análisis",
        "Consultar diagnóstico",
    ),
    "SCAN.DISCOVERY.ERROR": (
        "error", "ERROR", "No se pudo acceder a un objetivo",
        "Ver permisos y ruta",
    ),
}

_DESCRIPTIONS = {
    "SCAN.REPUTATION.UNCONFIGURED": (
        "No hay claves de reputación configuradas. El análisis continúa "
        "con los motores locales; no se enviaron hashes."
    ),
    "SCAN.YARA.UNAVAILABLE": (
        "No se pudo iniciar YARA. Los demás motores continúan, "
        "pero la cobertura de reglas es parcial."
    ),
    "SCAN.ENGINE.SKIPPED": (
        "Un componente no pudo revisar este objetivo. "
        "No significa que se haya detectado malware."
    ),
    "SCAN.ENGINE.UNAVAILABLE": (
        "Algunos componentes del sistema no pudieron inspeccionarse. "
        "Consulta los motivos antes de interpretar el resultado."
    ),
    "SCAN.ENGINE.ERROR": (
        "No se pudo completar una comprobación. "
        "El error no constituye por sí mismo una infección."
    ),
    "SCAN.INIT.FAILED": (
        "Un componente necesario falló antes del análisis. "
        "El resultado no es concluyente; consulta el registro técnico."
    ),
    "SCAN.DISCOVERY.ERROR": (
        "Un archivo o carpeta no pudo descubrirse. "
        "Esta parte del análisis tiene cobertura incompleta."
    ),
}


def make_event(
    kind: str, code: str, *, engine: str = "", path: str = "",
    params: dict[str, Any] | None = None, message: str = "",
    scan_id: str = "", target_id: str = "",
) -> ScanEvent:
    """Create a versioned event while preserving the legacy kind/payload API."""
    if code not in _CATALOG:
        raise ValueError(f"Código de evento desconocido: {code}")
    category, level, _title, action = _CATALOG[code]
    values = dict(params or {})
    payload: dict[str, Any] = {
        "schema_version": 1,
        "event_id": uuid4().hex,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "event_code": code,
        "scan_id": scan_id,
        "target_id": target_id,
        "title_key": code,
        "category": category,
        "level": level,
        "engine": engine,
        "path": path,
        "message_params": values,
        "dedupe_key": f"{code}:{engine or 'core'}",
        "recommended_action": action,
    }
    if message:
        payload["message"] = message
    return ScanEvent(kind, payload)


def present_event(event: ScanEvent) -> ClientMessage:
    """Render a safe title and explanation, preserving older event producers."""
    payload = event.payload
    code = str(payload.get("event_code", ""))
    if code not in _CATALOG:
        raw = str(payload.get("message", ""))
        if event.kind == "skipped":
            code = "SCAN.ENGINE.SKIPPED"
        elif event.kind == "error":
            code = "SCAN.ENGINE.ERROR"
        elif event.kind == "warning":
            # Legacy pre-v2 producer compatibility; never count missing API
            # credentials as a loss of local malware-detection coverage.
            code = ("SCAN.REPUTATION.UNCONFIGURED"
                    if "reputación externa" in raw.casefold()
                    and "api key" in raw.casefold()
                    else "SCAN.ENGINE.UNAVAILABLE")
        else:
            raise ValueError(f"Evento no representable: {event.kind}")
    category, level, title, action = _CATALOG[code]
    params = payload.get("message_params") or {}
    description = _DESCRIPTIONS.get(code, "")
    if code == "SCAN.YARA.SIZE_LIMIT":
        limit = params.get("limit_bytes")
        size = params.get("size_bytes")
        if isinstance(limit, int) and limit > 0:
            description = f"El archivo supera el límite YARA de {limit / 1048576:g} MiB."
            if isinstance(size, int) and size >= 0:
                description += f" Tamaño observado: {size / 1048576:.1f} MiB."
            description += " Otros motores pueden haberlo revisado."
        else:
            description = "YARA omitió un archivo grande. Otros motores pueden haberlo revisado."
    return ClientMessage(
        code=code,
        category=category,
        level=level,
        title=title,
        description=description,
        action=action,
        dedupe_key=str(payload.get("dedupe_key") or f"{code}:{payload.get('engine') or 'core'}"),
    )
