"""Opt-in, reversible disabling of *only* HKCU Run/RunOnce values on Windows.

Does not modify HKLM, tasks, services, Startup files, or arbitrary registry keys.
It refuses to run if the observed command has changed since scanning.
"""
from __future__ import annotations

import hashlib
import os
from uuid import uuid4

from core.remediation_policy import RemediationDenied, require_approval
from db.database import SQLiteStore, utc_now

try:
    import winreg
except ImportError:
    winreg = None

_ALLOWED = (
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
)


class PersistenceResponse:
    """Disable a narrow Windows user autorun with durable rollback metadata."""

    def __init__(self, store: SQLiteStore) -> None:
        self.store = store

    def disable_hkcu_run(self, finding_id: int, *, confirmation: str) -> str:
        """Back up the exact Run value in SQLite before removing it."""
        require_approval(confirmation, "DESACTIVAR INICIO")
        if os.name != "nt" or winreg is None:
            raise RemediationDenied("Operación disponible únicamente en Windows")
        import json
        with self.store.connection() as conn:
            finding = conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
            if finding is None or finding["suppressed"]:
                raise RemediationDenied("Hallazgo inexistente o excluido")
            signals = conn.execute("SELECT engine,details_json FROM evidence WHERE finding_id=?",
                                   (finding_id,)).fetchall()
        matches = []
        for signal in signals:
            if signal["engine"] == "persistence":
                data = json.loads(signal["details_json"])
                if data.get("source_type") == "registry":
                    matches.append(data)
        if len(matches) != 1:
            raise RemediationDenied("Se requiere una única evidencia de autorun HKCU")
        entry = matches[0].get("source_entry", "")
        parts = entry.split("\\")
        if len(parts) < 3 or parts[0] != "HKCU":
            raise RemediationDenied("Solo se admite HKCU Run/RunOnce")
        key_path = "\\".join(parts[1:-1])
        value_name = parts[-1]
        if key_path not in _ALLOWED or not value_name:
            raise RemediationDenied("Clave de registro fuera del alcance permitido")
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0,
                            winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE) as key:
            value, value_type = winreg.QueryValueEx(key, value_name)
            if not isinstance(value, str) or value_type not in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
                raise RemediationDenied("Tipo de valor no soportado")
            digest = hashlib.sha256(value[:4096].encode("utf-8")).hexdigest()
            if digest != matches[0].get("command_sha256"):
                raise RemediationDenied("La entrada cambió; vuelve a analizar")
            operation_id = uuid4().hex
            now = utc_now()
            with self.store.connection() as conn:
                conn.execute("INSERT INTO disabled_autoruns VALUES (?,?,?,?,?,?,?,?,?,?)",
                             (operation_id, finding_id, "HKCU", key_path, value_name, value,
                              value_type, "prepared", now, now))
            winreg.DeleteValue(key, value_name)
        with self.store.connection() as conn:
            conn.execute("UPDATE disabled_autoruns SET status='disabled',updated_at=? WHERE id=?",
                         (utc_now(), operation_id))
            conn.execute("INSERT INTO audit_log(event,detail_json,at) VALUES(?,?,?)",
                         ("autorun_disabled", json.dumps({"operation_id": operation_id}), utc_now()))
        return operation_id

    def restore_hkcu_run(self, operation_id: str, *, confirmation: str) -> None:
        """Restore a disabled autorun only when its old name is still absent."""
        require_approval(confirmation, "RESTAURAR INICIO")
        if os.name != "nt" or winreg is None:
            raise RemediationDenied("Operación disponible únicamente en Windows")
        with self.store.connection() as conn:
            row = conn.execute("SELECT * FROM disabled_autoruns WHERE id=?", (operation_id,)).fetchone()
        if row is None or row["status"] != "disabled" or row["hive"] != "HKCU" or row["key_path"] not in _ALLOWED:
            raise RemediationDenied("No se puede restaurar esta entrada")
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, row["key_path"], 0,
                            winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE) as key:
            try:
                winreg.QueryValueEx(key, row["value_name"])
            except FileNotFoundError:
                pass
            else:
                raise RemediationDenied("Ya existe una entrada con ese nombre; no se sobrescribe")
            winreg.SetValueEx(key, row["value_name"], 0, row["value_type"], row["value_data"])
        with self.store.connection() as conn:
            conn.execute("UPDATE disabled_autoruns SET status='restored',updated_at=? WHERE id=?",
                         (utc_now(), operation_id))
