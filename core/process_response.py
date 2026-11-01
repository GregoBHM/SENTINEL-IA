"""Guarded manual termination of a specific, unchanged process instance."""
from __future__ import annotations

import os
from pathlib import Path

from core.remediation_policy import RemediationDenied, require_approval, validate_mutable_file
from db.database import SQLiteStore

try:
    import psutil
except ImportError:
    psutil = None

_CRITICAL = {"system", "registry", "idle", "lsass.exe", "csrss.exe", "smss.exe",
             "services.exe", "winlogon.exe", "wininit.exe", "svchost.exe",
             "explorer.exe", "dwm.exe", "securityhealthservice.exe", "msmpeng.exe"}


class ProcessResponse:
    """Only terminate an identity-matched, noncritical process after approval."""

    def __init__(self, store: SQLiteStore) -> None:
        self.store = store

    def terminate(self, pid: int, started: float, executable: str, *, confirmation: str) -> None:
        """Request termination and wait briefly; never force-kill or use process names."""
        require_approval(confirmation, "FINALIZAR PROCESO")
        if os.name != "nt" or psutil is None:
            raise RemediationDenied("Finalización disponible únicamente en Windows")
        if pid <= 4 or pid == os.getpid():
            raise RemediationDenied("PID protegido")
        try:
            process = psutil.Process(pid)
            if abs(process.create_time() - started) > 0.5:
                raise RemediationDenied("El PID se reutilizó desde el análisis")
            if process.name().casefold() in _CRITICAL:
                raise RemediationDenied("Proceso Windows protegido")
            current_executable = process.exe()
            if Path(current_executable).resolve() != Path(executable).resolve():
                raise RemediationDenied("El ejecutable cambió desde el análisis")
            validate_mutable_file(Path(executable))
            process.terminate()
            try:
                process.wait(timeout=3)
            except psutil.TimeoutExpired:
                raise RemediationDenied("No finalizó en 3 segundos; no se forzó su cierre")
        except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            raise RemediationDenied("Proceso inaccesible o ya cerrado") from exc
        import json
        from db.database import utc_now
        with self.store.connection() as conn:
            conn.execute("INSERT INTO audit_log(event,detail_json,at) VALUES(?,?,?)",
                         ("process_terminated", json.dumps({"pid": pid, "started": started}), utc_now()))

    def terminate_finding(self, finding_id: int, *, confirmation: str) -> None:
        """Derive process identity exclusively from stored scanner evidence."""
        import json
        with self.store.connection() as conn:
            finding = conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
            if finding is None or finding["suppressed"] or not finding["target_path"].startswith("process_"):
                raise RemediationDenied("Se requiere un hallazgo activo de proceso")
            signals = conn.execute("SELECT engine,details_json FROM evidence WHERE finding_id=?",
                                   (finding_id,)).fetchall()
        matches = []
        for signal in signals:
            if signal["engine"] == "process_network":
                details = json.loads(signal["details_json"])
                if all(key in details for key in ("pid", "process_start", "executable_path")):
                    matches.append(details)
        if len(matches) != 1 or matches[0]["process_start"] is None:
            raise RemediationDenied("La identidad de proceso no se pudo verificar")
        identity = matches[0]
        if finding["target_path"] != f"process_{identity['pid']}":
            raise RemediationDenied("PID de evidencia inconsistente")
        self.terminate(int(identity["pid"]), float(identity["process_start"]),
                       str(identity["executable_path"]), confirmation=confirmation)
