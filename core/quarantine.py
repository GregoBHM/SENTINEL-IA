"""Explicit, reversible quarantine of reviewed local file findings.

Quarantine uses same-volume rename, never copy-then-delete across volumes.
Changes are journaled as state transitions in SQLite. Unknown states require
manual inspection rather than automatic cleanup after crashes.
"""
from __future__ import annotations

import os
import re
import sqlite3
import subprocess
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from core.remediation_policy import (
    RemediationDenied, require_approval, sha256_file, validate_mutable_file,
    validate_restore_parent,
)
from db.database import SQLiteStore, utc_now


def quarantine_directory() -> Path:
    """Return a data directory that is separate from the PyInstaller bundle."""
    if os.name == "nt":
        return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "SentinelOneGuard" / "Quarantine"
    from app.config import data_directory
    return data_directory() / "Quarantine"


def _trusted_icacls() -> str:
    """Resolve icacls via the OS system-directory API, never via PATH/CWD."""
    if os.name != "nt":
        raise RemediationDenied("Herramienta ACL disponible solo en Windows")
    import ctypes
    buffer = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetSystemDirectoryW(buffer, len(buffer))
    if length == 0 or length >= len(buffer):
        raise RemediationDenied("No se pudo consultar el directorio Windows")
    result = Path(buffer.value) / "icacls.exe"
    if not result.is_file():
        raise RemediationDenied("icacls del sistema no disponible")
    return str(result)


def _lock_down(path: Path, *, directory: bool) -> None:
    """Apply fail-closed filesystem restrictions before marking success.

    Windows: remove inherited ACEs and grant SYSTEM/Administrators only;
    deny execute on stored blobs. This requires an elevated token.
    """
    if os.name != "nt":
        path.chmod(0o700 if directory else 0o600)
        return
    icacls = _trusted_icacls()
    grants = ["*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"] if directory else [
        "*S-1-5-18:F", "*S-1-5-32-544:F"]
    commands = [
        [icacls, str(path), "/inheritance:r"],
        [icacls, str(path), "/grant:r", *grants],
    ]
    if not directory:
        commands.append([icacls, str(path), "/deny", "*S-1-1-0:X"])
    for cmd in commands:
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=10, check=False,
                                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RemediationDenied("No se pudo establecer ACL segura") from exc
        if result.returncode != 0:
            raise RemediationDenied("El control ACL de cuarentena falló")


@dataclass(frozen=True, slots=True)
class QuarantineItem:
    """Persistent identity and state of one quarantined object."""

    id: str
    finding_id: int
    original_path: str
    stored_path: str
    sha256: str
    size: int
    status: str
    created_at: str
    updated_at: str
    last_error: str | None = None


class QuarantineService:
    """Handle approved file movements with immutable-hash verification."""

    def __init__(self, store: SQLiteStore, vault: Path | None = None) -> None:
        """Create an isolated vault; refuse arbitrary Windows vault paths."""
        self.store = store
        default = quarantine_directory()
        self.vault = Path(vault or default).absolute()
        if os.name == "nt" and self.vault != default.absolute():
            raise RemediationDenied("El directorio de cuarentena Windows no es configurable")
        # Reject existing redirects into unrelated directories.
        if self.vault.is_symlink() or (hasattr(self.vault, "is_junction") and self.vault.is_junction()):
            raise RemediationDenied("Cuarentena enlazada a otra ubicación")
        self.vault.mkdir(parents=True, exist_ok=True, mode=0o700)
        from core.remediation_policy import _reject_reparse_chain
        _reject_reparse_chain(self.vault)
        _lock_down(self.vault, directory=True)

    def items(self, limit: int = 100) -> list[QuarantineItem]:
        """List recent quarantine state, including interrupted transitions."""
        with self.store.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM quarantine_items ORDER BY created_at DESC LIMIT ?",
                (min(max(limit, 1), 1000),),
            ).fetchall()
        return [QuarantineItem(**dict(row)) for row in rows]

    def _row(self, item_id: str) -> QuarantineItem:
        """Fetch one exact record; reject malicious path-like record IDs."""
        if not re.fullmatch(r"[0-9a-f]{32}", item_id):
            raise RemediationDenied("Identificador de cuarentena no válido")
        with self.store.connection() as conn:
            row = conn.execute("SELECT * FROM quarantine_items WHERE id=?", (item_id,)).fetchone()
        if row is None:
            raise RemediationDenied("Identificador de cuarentena inexistente")
        return QuarantineItem(**dict(row))

    def _status(self, item_id: str, status: str, error: str | None = None) -> None:
        """Persist a state change before performing the next action."""
        with self.store.connection() as conn:
            conn.execute("UPDATE quarantine_items SET status=?,updated_at=?,last_error=? WHERE id=?",
                         (status, utc_now(), error, item_id))

    def _audit(self, event: str, item_id: str, finding_id: int) -> None:
        """Write a minimal security audit record without reading private content."""
        import json
        with self.store.connection() as conn:
            conn.execute("INSERT INTO audit_log(event,detail_json,at) VALUES(?,?,?)",
                         (event, json.dumps({"item_id": item_id, "finding_id": finding_id}), utc_now()))

    def quarantine(self, finding_id: int, *, confirmation: str) -> QuarantineItem:
        """Move a hash-verified finding into an ACL-restricted, extensionless vault.

        The confirmed file must match both the finding SHA-256 and scan-target
        fingerprint, and must reside on the vault's volume. No overwrites.
        """
        require_approval(confirmation, "CUARENTENA")
        with self.store.connection() as conn:
            finding = conn.execute(
                "SELECT id,session_id,target_path,sha256,suppressed FROM findings WHERE id=?",
                (finding_id,),
            ).fetchone()
            if finding is None or finding["suppressed"] or not finding["sha256"]:
                raise RemediationDenied("Se requiere un hallazgo de archivo con SHA-256 y sin exclusión")
            target = conn.execute(
                "SELECT sha256,status FROM scan_targets WHERE session_id=? AND target_path=?",
                (finding["session_id"], finding["target_path"]),
            ).fetchone()
            if target is None or target["status"] not in {"scanned", "partial"} or target["sha256"] != finding["sha256"]:
                raise RemediationDenied("La evidencia no corresponde a un archivo inspeccionado")
            in_progress = conn.execute(
                "SELECT COUNT(*) FROM quarantine_items WHERE finding_id=? AND status IN ('prepared','quarantined','restoring','needs_review','deleting')",
                (finding_id,),
            ).fetchone()[0]
            if in_progress:
                raise RemediationDenied("Ya existe una operación activa para este hallazgo")
        origin = validate_mutable_file(Path(finding["target_path"]), vault=self.vault)
        expected = finding["sha256"].lower()
        current, size = sha256_file(origin)
        if current != expected:
            raise RemediationDenied("El archivo cambió después del análisis; analízalo de nuevo")
        if origin.stat().st_dev != self.vault.stat().st_dev:
            raise RemediationDenied("Volumen distinto: se bloquea copia y borrado no atómico")
        item_id = uuid4().hex
        destination = self.vault / f"{item_id}.blob"
        created = utc_now()
        with self.store.connection() as conn:
            conn.execute(
                "INSERT INTO quarantine_items VALUES(?,?,?,?,?,?,?,?,?,?)",
                (item_id, finding_id, str(origin), str(destination), expected,
                 size, "prepared", created, created, None),
            )
        moved = False
        try:
            # Best-effort race prevention: repeat checks immediately before rename.
            validate_mutable_file(origin, vault=self.vault)
            if sha256_file(origin) != (expected, size):
                raise RemediationDenied("Contenido modificado antes de la cuarentena")
            if destination.exists():
                raise RemediationDenied("El destino de cuarentena ya existe")
            # Windows rename fails if the destination unexpectedly exists,
            # whereas replace would silently overwrite it.
            os.rename(origin, destination) if os.name == "nt" else os.replace(origin, destination)
            moved = True
            _lock_down(destination, directory=False)
            if sha256_file(destination) != (expected, size):
                raise RemediationDenied("El archivo trasladado no coincide")
            self._status(item_id, "quarantined")
            self._audit("quarantined", item_id, finding_id)
        except Exception as exc:
            # Avoid silently losing a file. If reversal fails, request inspection.
            if moved and destination.exists() and not origin.exists():
                try:
                    os.rename(destination, origin) if os.name == "nt" else os.replace(destination, origin)
                    if os.name == "nt":
                        reset = subprocess.run([_trusted_icacls(), str(origin), "/reset"],
                            capture_output=True, timeout=10, check=False,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                        if reset.returncode != 0:
                            raise RemediationDenied("ACL no restaurada después de rollback")
                    self._status(item_id, "failed", type(exc).__name__)
                except Exception:
                    self._status(item_id, "needs_review", type(exc).__name__)
            else:
                self._status(item_id, "failed", type(exc).__name__)
            raise
        return self._row(item_id)

    def restore(self, item_id: str, *, confirmation: str) -> QuarantineItem:
        """Restore exactly to an absent, safe original destination; never overwrite."""
        require_approval(confirmation, "RESTAURAR")
        item = self._row(item_id)
        if item.status != "quarantined":
            raise RemediationDenied("Solo se restauran archivos en cuarentena")
        blob = self.vault / (item.id + ".blob")
        if (blob.parent != self.vault or Path(item.stored_path) != blob or
                blob.is_symlink() or not blob.is_file() or blob.stat().st_nlink != 1):
            raise RemediationDenied("Objeto de cuarentena no válido")
        if sha256_file(blob) != (item.sha256, item.size):
            raise RemediationDenied("Integridad de cuarentena incorrecta")
        origin = validate_restore_parent(Path(item.original_path), vault=self.vault)
        if origin.parent.stat().st_dev != self.vault.stat().st_dev:
            raise RemediationDenied("Volumen incompatible para restauración atómica")
        self._status(item_id, "restoring")
        moved = False
        try:
            validate_restore_parent(origin, vault=self.vault)
            os.rename(blob, origin) if os.name == "nt" else os.replace(blob, origin)
            moved = True
            if os.name == "nt":
                # Restore normal parent ACL inheritance; do not retain vault's
                # execute-deny ACE on a restored application binary.
                result = subprocess.run(
                    [_trusted_icacls(), str(origin), "/reset"], capture_output=True,
                    timeout=10, check=False,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                if result.returncode != 0:
                    raise RemediationDenied("Windows no pudo restablecer los permisos")
            else:
                origin.chmod(0o600)
            self._status(item_id, "restored")
            self._audit("restored", item_id, item.finding_id)
        except Exception as exc:
            # Restore a known-good quarantine state if possible; any failure
            # must be visible, never hidden behind a success message.
            if moved and origin.exists() and not blob.exists():
                try:
                    os.replace(origin, blob)
                    _lock_down(blob, directory=False)
                    self._status(item_id, "quarantined", type(exc).__name__)
                except Exception:
                    self._status(item_id, "needs_review", type(exc).__name__)
            elif self._row(item_id).status == "restoring":
                self._status(item_id, "needs_review", type(exc).__name__)
            raise
        return self._row(item_id)

    def delete(self, item_id: str, *, confirmation: str) -> QuarantineItem:
        """Delete only quarantined blobs; never delete an arbitrary user path."""
        require_approval(confirmation, "ELIMINAR DEFINITIVAMENTE")
        item = self._row(item_id)
        if item.status != "quarantined":
            raise RemediationDenied("El elemento no se encuentra en cuarentena")
        blob = self.vault / (item.id + ".blob")
        if (blob.parent != self.vault or Path(item.stored_path) != blob or
                blob.is_symlink() or not blob.is_file() or blob.stat().st_nlink != 1):
            raise RemediationDenied("Ruta de cuarentena inválida")
        if sha256_file(blob) != (item.sha256, item.size):
            raise RemediationDenied("No se puede verificar integridad de cuarentena")
        self._status(item_id, "deleting")
        try:
            blob.unlink()
            self._status(item_id, "deleted")
            self._audit("deleted", item_id, item.finding_id)
        except Exception as exc:
            self._status(item_id, "needs_review", type(exc).__name__)
            raise
        return self._row(item_id)
