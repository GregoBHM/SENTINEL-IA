"""Opt-in YARA-X backend for controlled compatibility evaluation.

Classic YARA remains the production default. YARA-X is never downloaded at
runtime or silently substituted when its native wheel or rule compilation fails.
"""
from __future__ import annotations

from pathlib import Path

from core.aggregator import severity_from_score
from core.detection_engine import DetectionEngine
from core.errors import RuleLoadError, ScanSkipped
from core.models import Finding, ScanTarget
from engines.yara_matches import RuleMatch, normalized_yarax

try:
    import yara_x
except ImportError:
    yara_x = None


class YaraXEngine(DetectionEngine):
    """Use YARA-X rules with isolated per-invocation scanner objects."""

    name = "yara"
    backend = "yarax"

    def __init__(
        self, rule_directory: Path, *, max_file_size: int = 64 * 1024 * 1024,
        timeout_seconds: int = 20,
    ) -> None:
        """Compile the complete rule pack or explicitly report the failure."""
        if yara_x is None:
            raise RuleLoadError(
                "YARA-X no está instalado (evaluación opcional; se conserva YARA)"
            )
        if max_file_size <= 0 or timeout_seconds <= 0:
            raise ValueError("Los límites de YARA-X deben ser positivos")
        folder = Path(rule_directory)
        paths = sorted(
            p for p in folder.rglob("*")
            if p.is_file() and p.suffix.lower() in {".yar", ".yara"}
            and not p.is_symlink()
        )
        if not paths or len(paths) > 10000:
            raise RuleLoadError("YARA-X necesita entre 1 y 10000 archivos de reglas")
        compiler = yara_x.Compiler()
        # Do not expand user-provided paths outside the approved rule directory.
        compiler.enable_includes(False)
        total_size = 0
        try:
            for index, path in enumerate(paths):
                data = path.read_bytes()
                total_size += len(data)
                if len(data) > 4 * 1024 * 1024 or total_size > 32 * 1024 * 1024:
                    raise RuleLoadError("Conjunto de reglas YARA-X demasiado grande")
                compiler.new_namespace(f"rule_{index}")
                compiler.add_source(data.decode("utf-8-sig"), origin=str(path))
            self._rules = compiler.build()
        except (OSError, UnicodeError, RuleLoadError) as exc:
            raise RuleLoadError(
                f"No se pudo preparar YARA-X: {type(exc).__name__}: {exc}"
            ) from exc
        except Exception as exc:
            raise RuleLoadError(
                f"Reglas incompatibles con YARA-X: {type(exc).__name__}: {exc}"
            ) from exc
        self.rule_count = len(paths)
        self.max_file_size = max_file_size
        self.timeout_seconds = timeout_seconds

    def applies_to(self, target: ScanTarget, file_header: bytes | None = None) -> bool:
        """Only real files can be scanned with file-pattern rules."""
        return target.kind == "file"

    def _scanner(self):
        """Create a scanner per invocation to avoid thread-shared scanner state."""
        scanner = yara_x.Scanner(self._rules)
        scanner.set_timeout(self.timeout_seconds)
        return scanner

    def match_bytes(self, data: bytes) -> list[RuleMatch]:
        """Inspect bounded in-memory payloads, also used for ZIP members."""
        if len(data) > self.max_file_size:
            raise ScanSkipped(
                "YARA-X omitió contenido superior a su límite",
                code="SCAN.YARA.SIZE_LIMIT",
                params={
                    "size_bytes": len(data),
                    "limit_bytes": self.max_file_size,
                },
            )
        try:
            return normalized_yarax(self._scanner().scan(data))
        except yara_x.TimeoutError as exc:
            raise ScanSkipped(
                "YARA-X agotó el tiempo máximo en contenido interno",
                code="SCAN.YARA.TIMEOUT",
                params={"timeout_seconds": self.timeout_seconds},
            ) from exc

    def scan(self, target: ScanTarget) -> list[Finding]:
        """Inspect one file without executing it or making network requests."""
        if target.kind != "file":
            return []
        size = target.path.stat().st_size
        if size > self.max_file_size:
            raise ScanSkipped(
                "YARA-X omitido: archivo superior al límite configurado",
                code="SCAN.YARA.SIZE_LIMIT",
                params={"size_bytes": size, "limit_bytes": self.max_file_size},
            )
        try:
            matches = normalized_yarax(self._scanner().scan_file(str(target.path)))
        except yara_x.TimeoutError as exc:
            raise ScanSkipped(
                "YARA-X agotó el tiempo máximo de análisis",
                code="SCAN.YARA.TIMEOUT",
                params={"timeout_seconds": self.timeout_seconds},
            ) from exc
        output: list[Finding] = []
        for rule in matches:
            meta = rule.meta
            test_only = bool(meta.get("test_only", False))
            try:
                score = (
                    0 if test_only
                    else max(0, min(100, int(meta.get("risk_score", 45))))
                )
                confidence = max(0, min(100, int(meta.get("confidence", 55))))
            except (ValueError, TypeError):
                score, confidence = 45, 55
            technique = str(meta.get("mitre", "")).strip()
            output.append(Finding(
                target=str(target.path), engine=self.name,
                threat_type=str(meta.get("threat_type") or "Patrón YARA")[:128],
                reason=str(
                    meta.get("description") or f"Regla coincidente: {rule.rule}"
                )[:500],
                severity=severity_from_score(score), risk_score=score,
                confidence=confidence, rule_id=rule.rule,
                evidence_group=str(meta.get("evidence_group") or rule.rule),
                mitre_techniques=(technique,) if technique else (),
                details={
                    "namespace": rule.namespace,
                    "tags": list(rule.tags),
                    "test_only": test_only,
                    "backend": self.backend,
                },
            ))
        return output
