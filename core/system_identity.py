"""Cautious, read-only identities for Windows process and autorun observations.

Process identity means a PID plus its creation timestamp observed at scan time.
An autorun reference is a configured command, not proof of process execution.
No file is executed, modified, hashed or transmitted by this module.
"""
from __future__ import annotations

import hashlib
import math
import ntpath
import re
from dataclasses import dataclass

from core.models import ScanTarget


_ABSOLUTE_DRIVE = re.compile(r"^[A-Za-z]:\\[^\x00\r\n]+$")
_UNQUOTED = re.compile(
    r"^([A-Za-z]:\\[^\s\"<>|\r\n]+\.(?:exe|com|scr|bat|cmd|ps1|vbs|js))"
    r"(?=\s|$)", re.IGNORECASE,
)
# Hosts may run arbitrary scripts, DLLs or commands. Matching their path to an
# active interpreter would misrepresent the actual persistence payload.
_HOSTS = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "rundll32.exe", "regsvr32.exe", "mshta.exe", "msiexec.exe",
    "python.exe", "pythonw.exe", "java.exe", "javaw.exe", "svchost.exe",
}


@dataclass(frozen=True, slots=True)
class SystemObservation:
    """A local observation, not a malware verdict or evidence of execution."""

    target_path: str
    kind: str
    status: str
    executable_path: str = ""
    normalized_executable: str = ""
    pid: int | None = None
    create_time: float | None = None
    source_entry: str = ""
    source_type: str = ""
    command_sha256: str = ""
    note: str = ""


def normalize_windows_executable(value: str) -> str:
    """Normalize a strict local drive path without touching the filesystem."""
    candidate = value.strip().strip('"')
    if len(candidate) > 2048 or not _ABSOLUTE_DRIVE.fullmatch(candidate):
        return ""
    if "%" in candidate or any(part == ".." for part in candidate.split("\\")):
        return ""
    return ntpath.normcase(ntpath.normpath(candidate))


def direct_autostart_executable(command: str) -> tuple[str, str]:
    """Return only unambiguous direct local executable references.

    Commands interpreted by shells, scripts/COM, bare PATH executables,
    unquoted paths with spaces, UNC shares and environment-variable placeholders
    are not correlated. This is deliberately stricter than heuristic scanning.
    """
    value = command.strip()
    if not value or len(value) > 4096 or any(x in value for x in ("\x00", "\r", "\n")):
        return "", "Comando vacío o inválido"
    if value.startswith('"'):
        closing = value.find('"', 1)
        if closing < 2 or (len(value) > closing + 1 and not value[closing + 1].isspace()):
            return "", "Ruta entre comillas no delimitada"
        candidate = value[1:closing]
    else:
        matched = _UNQUOTED.match(value)
        if not matched:
            return "", "Comando no directo o ruta ambigua"
        candidate = matched.group(1)
    normalized = normalize_windows_executable(candidate)
    if not normalized:
        return "", "Ruta no absoluta o con variables sin resolver"
    if ntpath.splitext(normalized)[1] not in {".exe", ".com", ".scr"}:
        return "", "Script o biblioteca requiere interpretar argumentos"
    if ntpath.basename(normalized) in _HOSTS:
        return "", "Host o intérprete: los argumentos requieren análisis aparte"
    return candidate, ""


def observe_process_identity(target: ScanTarget, process_api: object) -> SystemObservation:
    """Verify PID reuse against creation time before trusting an EXE-path report."""
    base = dict(target_path=str(target.path), kind="process")
    if target.kind != "process" or process_api is None:
        return SystemObservation(**base, status="unavailable", note="Inventario de procesos no disponible")
    try:
        pid = int(target.metadata["pid"])
        started = float(target.metadata["create_time"])
        if pid <= 0 or not math.isfinite(started) or started <= 0:
            raise ValueError("identidad incompleta")
    except (ValueError, TypeError, KeyError):
        return SystemObservation(**base, status="incomplete", note="Falta PID o instante de creación válido")
    try:
        process = process_api.Process(pid)
        actual = float(process.create_time())
        if not math.isfinite(actual) or abs(actual - started) > 0.01:
            return SystemObservation(
                **base, status="stale", pid=pid, create_time=started,
                note="PID reutilizado o identidad modificada durante el análisis",
            )
        exe = str(process.exe() or "")
        normalized = normalize_windows_executable(exe)
        if not normalized:
            return SystemObservation(
                **base, status="incomplete", pid=pid, create_time=started,
                note="No se obtuvo una ruta local absoluta verificable",
            )
        return SystemObservation(
            **base, status="verified", pid=pid, create_time=started,
            executable_path=exe[:2048], normalized_executable=normalized,
            note="PID, hora de creación y ruta observados en esta instantánea",
        )
    except Exception as exc:
        # psutil's AccessDenied/NoSuchProcess and platform-specific errors
        # are observational limits, never evidence of malware.
        return SystemObservation(
            **base, status="unavailable", pid=pid, create_time=started,
            note=f"No fue posible consultar el proceso: {type(exc).__name__}",
        )


def observe_autostart_reference(target: ScanTarget) -> SystemObservation:
    """Record a hashed command and candidate EXE, never the raw command line."""
    if target.kind != "persistence":
        raise ValueError("Se esperaba un registro de persistencia")
    command = str(target.metadata.get("command") or "")[:4096]
    executable, reason = direct_autostart_executable(command)
    kind = str(target.metadata.get("source_type") or "unknown")[:40]
    if kind not in {"registry", "startup", "service", "task"}:
        kind = "unknown"
    return SystemObservation(
        target_path=str(target.path), kind="persistence",
        status="reference_only" if executable else "ambiguous",
        executable_path=executable[:2048],
        normalized_executable=normalize_windows_executable(executable),
        source_entry=str(target.metadata.get("entry") or target.path)[:1024],
        source_type=kind,
        command_sha256=hashlib.sha256(command.encode("utf-8")).hexdigest(),
        note="Referencia configurada; no demuestra ejecución"
             if executable else reason,
    )
