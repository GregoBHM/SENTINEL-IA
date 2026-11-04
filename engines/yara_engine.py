"""YARA rule scanner; compiling rules locally without running target code."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from core.aggregator import severity_from_score
from core.detection_engine import DetectionEngine
from core.errors import RuleLoadError, ScanSkipped
from core.models import Finding, ScanTarget
from engines.yara_matches import RuleMatch, normalized_classic

try:
    import yara
except ImportError:  # Allow hash-only scans when the optional native package is absent.
    yara = None  # type: ignore[assignment]


class YaraEngine(DetectionEngine):
    """Compile validated YARA files and scan bounded file contents."""

    name = "yara"

    def __init__(
        self, rule_directory: Path, *, max_file_size: int = 64 * 1024 * 1024,
        timeout_seconds: int = 20,
    ) -> None:
        """Compile rules once at startup and reject syntax failures explicitly."""
        if yara is None:
            raise RuleLoadError(
                "yara-python no está instalado; usar --no-yara o instalar dependencias"
            )
        directory = Path(rule_directory)
        files = sorted(
            f for f in directory.rglob("*")
            if f.is_file() and f.suffix.lower() in {".yar", ".yara"}
        )
        if not files:
            raise RuleLoadError(f"No se encontraron archivos .yar/.yara en: {directory}")
        if len(files) > 10000:
            raise RuleLoadError("Demasiados archivos de reglas")
        # A namespace per file prevents collisions of rule names across rule packs.
        filepaths = {f"rule_{index}": str(path) for index, path in enumerate(files)}
        try:
            self._rules = yara.compile(filepaths=filepaths)
        except Exception as exc:
            raise RuleLoadError(
                f"Error al compilar reglas YARA: {type(exc).__name__}: {exc}"
            ) from exc
        self.rule_count = len(files)
        self.max_file_size = max_file_size
        self.timeout_seconds = timeout_seconds

    def applies_to(self, target: ScanTarget, file_header: bytes | None = None) -> bool:
        """A loaded YARA ruleset may inspect any file type."""
        return target.kind == "file"

    def match_bytes(self, data: bytes) -> list[RuleMatch]:
        """Use the same match contract for local files and archive contents."""
        if len(data) > self.max_file_size:
            raise ScanSkipped(
                "YARA omitido: archivo interno superior al límite configurado",
                code="SCAN.YARA.SIZE_LIMIT",
                params={"size_bytes": len(data), "limit_bytes": self.max_file_size},
            )
        return normalized_classic(
            self._rules.match(data=data, timeout=self.timeout_seconds)
        )

    def scan(self, target: ScanTarget) -> list[Finding]:
        """Find matched YARA rules with bounded time and explainable metadata."""
        if target.kind != "file":
            return []
        size_bytes = target.path.stat().st_size
        if size_bytes > self.max_file_size:
            raise ScanSkipped(
                "YARA omitido: archivo superior al límite configurado",
                code="SCAN.YARA.SIZE_LIMIT",
                params={"size_bytes": size_bytes, "limit_bytes": self.max_file_size},
            )
        matches = normalized_classic(
            self._rules.match(filepath=str(target.path), timeout=self.timeout_seconds)
        )
        results: list[Finding] = []
        for match in matches:
            meta: dict[str, Any] = dict(match.meta or {})
            test_only = bool(meta.get("test_only", False))
            try:
                score = 0 if test_only else max(0, min(100, int(meta.get("risk_score", 45))))
                confidence = max(0, min(100, int(meta.get("confidence", 55))))
            except (ValueError, TypeError):
                score, confidence = 45, 55
            tech = str(meta.get("mitre", "")).strip()
            results.append(Finding(
                target=str(target.path),
                engine=self.name,
                threat_type=str(meta.get("threat_type") or "Patrón YARA")[:128],
                reason=str(meta.get("description") or f"Regla coincidente: {match.rule}")[:500],
                severity=severity_from_score(score), risk_score=score,
                confidence=confidence, rule_id=str(match.rule),
                evidence_group=str(meta.get("evidence_group") or match.rule),
                mitre_techniques=(tech,) if tech else (),
                details={"namespace": match.namespace, "tags": list(match.tags),
                         "test_only": test_only, "backend": "classic"},
            ))
        return results
