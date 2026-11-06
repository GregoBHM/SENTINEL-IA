"""Session-scoped, read-only coverage assessment for incident investigation.

Counts measure recorded observations and omitted checks, not malware absence.
This module never opens scanned files, contacts a server, or triggers mitigation.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from db.database import SQLiteStore


@dataclass(frozen=True, slots=True)
class InvestigationCoverage:
    session_id: str
    status: str
    scanned_files: int
    finding_files: int
    errors: int
    omitted_checks: int
    checks_finished: int
    checks_incomplete: int
    archive_inspected: int
    archive_incomplete: int
    file_identities_observed: int
    file_identities_incomplete: int
    processes_verified: int
    system_references_only: int
    system_incomplete: int

    @property
    def has_limits(self) -> bool:
        return (self.status != "completed"
                or bool(self.errors or self.omitted_checks
                        or self.checks_incomplete or self.archive_incomplete
                        or self.file_identities_incomplete or self.system_incomplete)
                or self.checks_finished == 0)

    def lines(self) -> tuple[str, ...]:
        """Spanish, privacy-safe explanations for the selected persisted session."""
        lines = [
            f"Estado de sesión: {self.status}. Archivos procesados: {self.scanned_files}; "
            f"objetivos con hallazgos: {self.finding_files}.",
            f"Comprobaciones finalizadas: {self.checks_finished}; "
            f"comprobaciones no completadas: {self.checks_incomplete}.",
            f"Archivos internos inspeccionados: {self.archive_inspected}; "
            f"parciales o sin inspeccionar: {self.archive_incomplete}.",
            f"Huellas de archivo observadas: {self.file_identities_observed}; "
            f"identidades incompletas: {self.file_identities_incomplete}.",
            f"Procesos con identidad verificada: {self.processes_verified}; "
            f"referencias de inicio (no ejecución confirmada): "
            f"{self.system_references_only}; observaciones de sistema "
            f"incompletas: {self.system_incomplete}.",
        ]
        if self.has_limits:
            lines.append(
                f"COBERTURA LIMITADA: {self.errors} errores y "
                f"{self.omitted_checks} omisiones registradas en la sesión; "
                "consulta las causas por archivo y motor."
            )
        else:
            lines.append(
                "No se registraron omisiones en estas categorías; esto NO "
                "equivale a inspección universal ni demuestra equipo limpio."
            )
        lines.append(
            "La falta de alertas no excluye malware, robo previo de datos, "
            "persistencia desconocida ni alteración del sistema."
        )
        return tuple(lines)


def read_investigation_coverage(
    store: "SQLiteStore", session_id: str,
) -> InvestigationCoverage:
    """Aggregate bounded SQL counts for exactly one session.

    Uses COUNT/SUM instead of transferring unbounded rows to the GUI. Old
    sessions with no target-level measurements remain explicitly uncertain.
    """
    if not session_id:
        raise ValueError("Se requiere identificador de sesión")
    with store.connection() as conn:
        session = conn.execute(
            """SELECT status,scanned_files,finding_files,errors,omitted_checks
               FROM scan_sessions WHERE id=?""", (session_id,),
        ).fetchone()
        if session is None:
            raise ValueError("Sesión no encontrada")

        engine = conn.execute(
            """SELECT
               COALESCE(SUM(CASE WHEN state='success' THEN 1 ELSE 0 END),0)
                   AS completed,
               COALESCE(SUM(CASE WHEN state IN
                   ('skipped','error','not_run') THEN 1 ELSE 0 END),0)
                   AS incomplete
               FROM scan_target_engines WHERE session_id=?""",
            (session_id,),
        ).fetchone()
        archive = conn.execute(
            """SELECT
               COALESCE(SUM(CASE WHEN status='inspected' THEN 1 ELSE 0 END),0)
                   AS inspected,
               COALESCE(SUM(CASE WHEN status!='inspected' THEN 1 ELSE 0 END),0)
                   AS incomplete
               FROM scan_archive_members WHERE session_id=?""",
            (session_id,),
        ).fetchone()
        identity = conn.execute(
            """SELECT
               COALESCE(SUM(CASE WHEN status='observed' THEN 1 ELSE 0 END),0)
                   AS observed,
               COALESCE(SUM(CASE WHEN status!='observed' THEN 1 ELSE 0 END),0)
                   AS incomplete
               FROM scan_file_identities WHERE session_id=?""",
            (session_id,),
        ).fetchone()
        system = conn.execute(
            """SELECT
               COALESCE(SUM(CASE WHEN kind='process' AND status='verified'
                   THEN 1 ELSE 0 END),0) AS verified,
               COALESCE(SUM(CASE WHEN status='reference_only'
                   THEN 1 ELSE 0 END),0) AS references_only,
               COALESCE(SUM(CASE WHEN status NOT IN ('verified','reference_only')
                   THEN 1 ELSE 0 END),0) AS incomplete
               FROM scan_system_observations WHERE session_id=?""",
            (session_id,),
        ).fetchone()

    return InvestigationCoverage(
        session_id=session_id, status=str(session["status"]),
        scanned_files=int(session["scanned_files"]),
        finding_files=int(session["finding_files"]),
        errors=int(session["errors"]),
        omitted_checks=int(session["omitted_checks"]),
        checks_finished=int(engine["completed"]),
        checks_incomplete=int(engine["incomplete"]),
        archive_inspected=int(archive["inspected"]),
        archive_incomplete=int(archive["incomplete"]),
        file_identities_observed=int(identity["observed"]),
        file_identities_incomplete=int(identity["incomplete"]),
        processes_verified=int(system["verified"]),
        system_references_only=int(system["references_only"]),
        system_incomplete=int(system["incomplete"]),
    )
