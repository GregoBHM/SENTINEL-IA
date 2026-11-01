"""Offline HTML/CSV reports generated from recorded observations, not guesses."""
from __future__ import annotations

import csv
import html
import io
import os
import sqlite3
import tempfile
from pathlib import Path

from db.database import SQLiteStore, utc_now


def _safe_csv_cell(value: object) -> str:
    """Keep spreadsheet programs from executing formulas in attacker-controlled paths."""
    content = str(value if value is not None else "")
    if content.lstrip().startswith(("=", "+", "-", "@", "\t", "\r", "\n")):
        return "'" + content
    return content


class ReportService:
    """Produce local, escaped reports with bounded queries and no external links."""

    def __init__(self, store: SQLiteStore) -> None:
        self.store = store

    def _data(self, session_id: str) -> tuple[dict, list[dict]]:
        """Read a completed or incomplete session without altering any evidence."""
        with self.store.connection() as conn:
            session = conn.execute("SELECT * FROM scan_sessions WHERE id=?", (session_id,)).fetchone()
            if session is None:
                raise ValueError("Sesión de análisis inexistente")
            rows = conn.execute(
                "SELECT * FROM findings WHERE session_id=? ORDER BY risk_score DESC, id LIMIT 10000",
                (session_id,),
            ).fetchall()
        return dict(session), [dict(row) for row in rows]

    def _write(self, destination: Path, contents: str) -> Path:
        """Create a new report without overwriting an existing user file."""
        output = Path(destination).expanduser().absolute()
        if output.exists() or output.is_symlink():
            raise FileExistsError(f"El informe ya existe: {output}")
        if not output.parent.is_dir() or output.parent.is_symlink():
            raise ValueError("Carpeta de informe no válida")
        # Temporary report is cleaned on error; no untrusted content is executed.
        descriptor, temporary = tempfile.mkstemp(prefix=".oneguard-", suffix=".tmp", dir=output.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
                handle.write(contents)
                handle.flush()
                os.fsync(handle.fileno())
            if output.exists():
                raise FileExistsError("El informe apareció durante la escritura")
            # Hard link guarantees no-overwrite on compatible local filesystems.
            os.link(temporary, output)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
        return output

    def export_csv(self, session_id: str, destination: Path) -> Path:
        """Export a UTF-8 CSV, prefixing dangerous spreadsheet-formula values."""
        session, findings = self._data(session_id)
        stream = io.StringIO(newline="")
        writer = csv.writer(stream)
        writer.writerow(["session_id", "session_status", "target", "threat_type",
                         "severity", "risk_score", "confidence", "reason",
                         "sha256", "engines", "suppressed", "timestamp"])
        for item in findings:
            writer.writerow([_safe_csv_cell(x) for x in (
                session["id"], session["status"], item["target_path"], item["threat_type"],
                item["severity"], item["risk_score"], item["confidence"], item["reason"],
                item["sha256"], item["engines_json"], item["suppressed"], item["created_at"],
            )])
        return self._write(destination, "\ufeff" + stream.getvalue())

    def export_html(self, session_id: str, destination: Path) -> Path:
        """Export HTML with all user-controlled fields HTML-escaped and no scripts."""
        session, findings = self._data(session_id)
        e = lambda x: html.escape(str(x if x is not None else ""), quote=True)
        rows = []
        for item in findings:
            cells = (item["severity"], item["risk_score"], item["confidence"],
                     item["threat_type"], item["target_path"], item["reason"],
                     item["sha256"] or "", item["engines_json"])
            rows.append("<tr>" + "".join(f"<td>{e(c)}</td>" for c in cells) + "</tr>")
        body = f'''<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Sentinel OneGuard — Informe {e(session_id)}</title>
<style>body{{font:15px system-ui;background:#0b1423;color:#eaf3ff;padding:32px}}
header{{border-bottom:1px solid #304255;padding-bottom:20px}}
h1{{color:#50d9ff}}small{{color:#a8b8cb}} table{{border-collapse:collapse;width:100%}}
th,td{{padding:9px;border-bottom:1px solid #2a384b;text-align:left;word-break:break-word}}
th{{color:#50d9ff}} .warn{{padding:12px;border:1px solid #8d6b3b}}</style></head><body>
<header><h1>Sentinel OneGuard · Informe de análisis</h1>
<p>Sesión: {e(session['id'])} | Estado: {e(session['status'])}</p>
<p>Inicio: {e(session['started_at'])} | Fin: {e(session['finished_at'])}</p>
<p>Archivos inspeccionados: {e(session['scanned_files'])} | Hallazgos: {len(findings)} | Errores: {e(session['errors'])}</p></header>
<p class="warn">Un hallazgo no demuestra infección por sí mismo. Un análisis sin alertas NO certifica un equipo limpio.
Las sesiones canceladas, errores y análisis parciales requieren investigación adicional.
Este documento puede contener rutas privadas: consérvalo de forma segura.</p>
<h2>Hallazgos</h2><table><thead><tr><th>Severidad</th><th>Riesgo</th><th>Confianza</th>
<th>Tipo</th><th>Objetivo</th><th>Motivo</th><th>SHA-256</th><th>Motores</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table><small>Informe local generado: {e(utc_now())}.
No se han enviado archivos ni credenciales.</small></body></html>'''
        return self._write(destination, body)
