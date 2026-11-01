"""Bounded archive scanner; opens members in memory, never extracts to disk.

ZIP members support recursive inspection; RAR requires a compatible external
backend and 7z uses py7zr if installed. Hard memory/process isolation remains
out of scope until a sandboxed worker is supplied.
"""
from __future__ import annotations

import hashlib
import io
import os
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from core.aggregator import severity_from_score
from core.detection_engine import DetectionEngine
from core.errors import ScanSkipped
from core.heuristics import has_misleading_extension
from core.models import Finding, ScanTarget, Severity
from db.database import SQLiteStore
from engines.script_engine import ScriptEngine
from engines.pe_engine import PEEngine

try:
    import rarfile
except ImportError:
    rarfile = None
try:
    import py7zr
except ImportError:
    py7zr = None

_ARCHIVES = {".zip", ".rar", ".7z"}


@dataclass(slots=True)
class ArchiveBudget:
    """Global depth, byte and entry counters shared by nested archives."""

    consumed: int = 0
    entries: int = 0
    deadline: float = 0.0


class ArchiveEngine(DetectionEngine):
    """Read-only bounded archive inspection for hashes, YARA and script heuristics."""

    name = "archive"

    def __init__(self, store: SQLiteStore | None = None, *, yara_engine: object = None,
                 script_engine: ScriptEngine | None = None, pe_engine: PEEngine | None = None,
                 max_depth: int = 3, max_entries: int = 10000,
                 max_total_bytes: int = 64 * 1024 * 1024,
                 max_member_bytes: int = 8 * 1024 * 1024,
                 max_seconds: int = 60) -> None:
        """Configure conservative in-memory extraction limits."""
        self.store = store
        self.yara_engine = yara_engine
        self.script_engine = script_engine or ScriptEngine()
        self.pe_engine = pe_engine or PEEngine()
        self.max_depth = max_depth
        self.max_entries = max_entries
        self.max_total_bytes = max_total_bytes
        self.max_member_bytes = max_member_bytes
        self.max_seconds = max_seconds
        if not (1 <= max_depth <= 10 and max_entries > 0 and
                0 < max_member_bytes <= max_total_bytes and max_seconds > 0):
            raise ValueError("Parámetros de archivo comprimido inválidos")

    def scan(self, target: ScanTarget) -> list[Finding]:
        """Read a supported container while tracking a shared resource budget."""
        if target.kind != "file" or target.path.suffix.lower() not in _ARCHIVES:
            return []
        if target.path.stat().st_size > self.max_total_bytes:
            raise ScanSkipped("Contenedor supera el límite de entrada")
        budget = ArchiveBudget(deadline=time.monotonic() + self.max_seconds)
        try:
            # Backends require seekable input; original archive size was bounded.
            with target.path.open("rb") as handle:
                blob = handle.read(self.max_total_bytes + 1)
            if len(blob) > self.max_total_bytes:
                raise ScanSkipped("Contenedor supera límite de memoria")
            return self._scan_blob(blob, target.path.name, str(target.path), 1, budget)
        except (zipfile.BadZipFile, OSError, ValueError, EOFError) as exc:
            raise ScanSkipped(f"Error de lectura de comprimido: {type(exc).__name__}") from exc

    def _report(self, target: str, code: str, reason: str, score: int = 0) -> Finding:
        """Make coverage gaps and archive filename warnings visible and auditable."""
        return Finding(
            target=target, engine=self.name, threat_type="Inspección de archivo comprimido"
            if not score else "Indicador en archivo comprimido",
            reason=reason, severity=severity_from_score(score), risk_score=score,
            confidence=35 if score else 100, rule_id=code,
            evidence_group="archive_metadata", details={"limitation": score == 0},
        )

    def _read_bounded(self, handle: BinaryIO, budget: ArchiveBudget) -> bytes:
        """Stream uncompressed bytes and enforce global & per-member ceilings."""
        chunks: list[bytes] = []
        size = 0
        while True:
            if time.monotonic() > budget.deadline:
                raise ScanSkipped("Tiempo de inspección del comprimido agotado")
            block = handle.read(min(65536, self.max_member_bytes - size + 1))
            if not block:
                break
            size += len(block)
            budget.consumed += len(block)
            if size > self.max_member_bytes or budget.consumed > self.max_total_bytes:
                raise ScanSkipped("Se alcanzó el límite de bytes descomprimidos")
            chunks.append(block)
        return b"".join(chunks)

    def _scan_blob(
        self, blob: bytes, name: str, label: str, depth: int, budget: ArchiveBudget
    ) -> list[Finding]:
        """Walk nested archives; all child labels retain the parent provenance."""
        if depth > self.max_depth:
            return [self._report(label, "depth_limit", "Contenido anidado no analizado: límite de profundidad")]
        if time.monotonic() > budget.deadline:
            return [self._report(label, "time_limit", "Inspección incompleta: límite de tiempo")]
        suffix = Path(name).suffix.lower()
        if suffix == ".zip":
            return self._scan_zip(blob, label, depth, budget)
        if suffix == ".rar":
            return self._scan_rar(blob, label, depth, budget)
        if suffix == ".7z":
            return self._scan_7z(blob, label, depth, budget)
        return self._inspect_payload(blob, name, label)

    def _visit(self, handle: BinaryIO, name: str, label: str,
               depth: int, budget: ArchiveBudget) -> list[Finding]:
        """Read an entry with the global budget and dispatch to engines."""
        budget.entries += 1
        if budget.entries > self.max_entries:
            return [self._report(label, "entry_limit", "Inspección incompleta: exceso de entradas")]
        findings = []
        unified = name.replace("\\", "/")
        components = PurePosixPath(unified).parts
        if (unified.startswith(("/", "\\")) or ".." in components or
                (len(unified) > 1 and unified[1] == ":")):
            findings.append(self._report(label, "unsafe_path", "Ruta peligrosa dentro del comprimido", 25))
        if has_misleading_extension(name):
            findings.append(self._report(label, "double_extension", "Nombre con doble extensión engañosa", 26))
        try:
            data = self._read_bounded(handle, budget)
        except ScanSkipped as exc:
            findings.append(self._report(label, "resource_limit", f"Inspección incompleta: {exc}"))
            return findings
        findings.extend(self._scan_blob(data, name, label, depth + 1, budget)
                        if Path(name).suffix.lower() in _ARCHIVES
                        else self._inspect_payload(data, name, label))
        return findings

    def _scan_zip(self, blob: bytes, label: str, depth: int,
                  budget: ArchiveBudget) -> list[Finding]:
        """Inspect ZIP entries, including encrypted and oversized coverage gaps."""
        findings = []
        try:
            with zipfile.ZipFile(io.BytesIO(blob)) as archive:
                for entry in archive.infolist():
                    if budget.entries >= self.max_entries:
                        findings.append(self._report(label, "entry_limit", "ZIP parcialmente analizado: límite de entradas"))
                        break
                    if time.monotonic() > budget.deadline:
                        findings.append(self._report(label, "time_limit", "Contenedor parcialmente analizado: tiempo agotado"))
                        break
                    if entry.is_dir():
                        continue
                    child = label + "::" + entry.filename
                    if entry.flag_bits & 0x1:
                        findings.append(self._report(child, "encrypted", "No se pudo inspeccionar: entrada cifrada"))
                        continue
                    if entry.file_size > self.max_member_bytes:
                        findings.append(self._report(child, "size_limit", "No inspeccionado: archivo interno demasiado grande"))
                        continue
                    if entry.compress_size and entry.file_size / entry.compress_size > 100:
                        findings.append(self._report(child, "expansion_ratio", "Relación de expansión elevada; inspección limitada"))
                    try:
                        with archive.open(entry) as stream:
                            findings.extend(self._visit(stream, entry.filename, child, depth, budget))
                    except (OSError, RuntimeError, zipfile.BadZipFile, EOFError, ValueError) as exc:
                        findings.append(self._report(child, "entry_error", f"Entrada no analizada: {type(exc).__name__}"))
                    if budget.entries > self.max_entries or budget.consumed > self.max_total_bytes:
                        break
        except (OSError, zipfile.BadZipFile, EOFError) as exc:
            findings.append(self._report(label, "invalid_zip", f"ZIP no inspeccionable: {type(exc).__name__}"))
        return findings

    def _scan_rar(self, blob: bytes, label: str, depth: int,
                  budget: ArchiveBudget) -> list[Finding]:
        """Use rarfile streaming backend when available; report missing backend."""
        if rarfile is None:
            return [self._report(label, "rar_dependency", "RAR no inspeccionado: instalar rarfile y backend compatible")]
        findings = []
        try:
            with rarfile.RarFile(io.BytesIO(blob)) as archive:
                for entry in archive.infolist():
                    if budget.entries >= self.max_entries:
                        findings.append(self._report(label, "entry_limit", "RAR parcialmente analizado: límite de entradas"))
                        break
                    if time.monotonic() > budget.deadline:
                        findings.append(self._report(label, "time_limit", "RAR parcialmente analizado: tiempo agotado"))
                        break
                    if entry.isdir():
                        continue
                    child = label + "::" + entry.filename
                    if entry.needs_password():
                        findings.append(self._report(child, "encrypted", "RAR cifrado; contenido no inspeccionado"))
                        continue
                    if entry.file_size > self.max_member_bytes:
                        findings.append(self._report(child, "size_limit", "RAR interno excede límite"))
                        continue
                    try:
                        with archive.open(entry) as stream:
                            findings.extend(self._visit(stream, entry.filename, child, depth, budget))
                    except Exception as exc:
                        findings.append(self._report(child, "rar_error", f"Entrada RAR inaccesible: {type(exc).__name__}"))
                    if budget.entries > self.max_entries:
                        break
        except Exception as exc:
            findings.append(self._report(label, "rar_error", f"RAR no inspeccionable: {type(exc).__name__}"))
        return findings

    def _scan_7z(self, blob: bytes, label: str, depth: int,
                 budget: ArchiveBudget) -> list[Finding]:
        """Use py7zr writer factory with per-member/global limits, no disk extraction."""
        if py7zr is None:
            return [self._report(label, "seven_zip_dependency", "7z no inspeccionado: instalar py7zr")]
        # py7zr extraction has no reliable wall-clock cancellation in-process.
        # To prevent an incorrect security claim, we inspect metadata here and
        # explicitly mark content as uninspected until an isolated worker exists.
        try:
            with py7zr.SevenZipFile(io.BytesIO(blob), mode="r") as archive:
                entries = archive.list()
                messages = [self._report(label + "::" + str(x.filename), "seven_zip_pending",
                           "7z: contenido pendiente de inspección en worker aislado")
                            for x in entries[:min(self.max_entries, 100)]]
                if len(entries) > 100:
                    messages.append(self._report(label, "entry_limit", "7z: inventario truncado"))
                return messages
        except Exception as exc:
            return [self._report(label, "seven_zip_error", f"7z no inspeccionable: {type(exc).__name__}")]

    def _inspect_payload(self, blob: bytes, name: str, label: str) -> list[Finding]:
        """Match local SHA-256, YARA data patterns and static script indicators."""
        findings: list[Finding] = []
        digest = hashlib.sha256(blob).hexdigest()
        if self.store is not None:
            signature = self.store.get_hash_signature(digest)
            if signature:
                score = int(signature["risk_score"])
                findings.append(Finding(
                    target=label, engine="hash", threat_type=signature["threat_type"],
                    reason="Hash SHA-256 de contenido comprimido coincide con firma local revisada",
                    risk_score=score, confidence=int(signature["confidence"]),
                    severity=severity_from_score(score), sha256=digest,
                    evidence_group="confirmed_hash", details={"contained_in_archive": True},
                ))
        if self.yara_engine is not None:
            try:
                matches = self.yara_engine._rules.match(data=blob, timeout=self.yara_engine.timeout_seconds)
                for match in matches:
                    metadata = dict(match.meta or {})
                    score = 0 if metadata.get("test_only") else min(80, max(0, int(metadata.get("risk_score", 45))))
                    findings.append(Finding(
                        target=label, engine="yara", threat_type=str(metadata.get("threat_type", "YARA")),
                        reason=str(metadata.get("description", "Regla YARA coincidente dentro de archivo comprimido")),
                        risk_score=score, confidence=50, severity=severity_from_score(score),
                        rule_id=str(match.rule), evidence_group=str(match.rule),
                        details={"contained_in_archive": True},
                    ))
            except Exception:
                findings.append(self._report(label, "yara_incomplete", "No se pudo completar YARA del archivo interno"))
        if Path(name).suffix.lower() in {".ps1", ".psm1", ".js", ".vbs", ".hta", ".bat", ".cmd"}:
            findings.extend(self.script_engine.inspect_bytes(blob, label))
        if Path(name).suffix.lower() in {".exe", ".dll", ".sys", ".scr"}:
            try:
                findings.extend(self.pe_engine.inspect_bytes(blob, label))
            except ScanSkipped as exc:
                findings.append(self._report(label, "pe_dependency", f"PE interno no analizado: {exc}"))
        return findings
