"""Script and macro heuristics: strings and structure only, never execution."""
from __future__ import annotations

import re
import zipfile
from pathlib import Path

from core.aggregator import severity_from_score
from core.detection_engine import DetectionEngine
from core.errors import ScanSkipped
from core.models import Finding, ScanTarget

_SCRIPT_SUFFIXES = {".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".bat", ".cmd", ".hta"}
_OFFICE_SUFFIXES = {".docm", ".xlsm", ".pptm"}
_FAMILIES: dict[str, tuple[str, ...]] = {
    "encoded_execution": (r"\-(?:encodedcommand|enc)\b", r"frombase64string\s*\(",
                          r"(?:powershell|pwsh)(?:\.exe)?\s+[^\n]*\-e(?:nc)?\b"),
    "download": (r"downloadstring\s*\(", r"invoke-webrequest\b", r"certutil(?:\.exe)?\s+-urlcache",
                 r"msxml2\.xmlhttp", r"bitsadmin\b"),
    "dynamic_execution": (r"\binvoke-expression\b", r"\biex\s*\(", r"\beval\s*\(",
                          r"wscript\.shell", r"\bexecute(?:global)?\s*\("),
    "persistence": (r"currentversion\\run(?:once)?", r"schtasks(?:\.exe)?\s+/create",
                    r"new-service\b", r"startup\\"),
    "security_interference": (r"set-mppreference\b", r"add-mppreference\b",
                              r"disableantispyware", r"disablebehaviormonitoring"),
}
_COMPILED = {key: tuple(re.compile(p, re.I) for p in patterns)
             for key, patterns in _FAMILIES.items()}


def indicators_from_script(data: bytes) -> list[str]:
    """Return category names, not contents, to avoid leaking script secrets."""
    text = data.decode("utf-8-sig", errors="replace")
    return [name for name, patterns in _COMPILED.items() if any(p.search(text) for p in patterns)]


class ScriptEngine(DetectionEngine):
    """Look for clusters of suspicious scripting constructs and macro indicators."""

    name = "script_static"

    def __init__(self, *, max_script_bytes: int = 2 * 1024 * 1024) -> None:
        """Limit memory consumed per input."""
        self.max_script_bytes = max_script_bytes

    def inspect_bytes(self, data: bytes, label: str) -> list[Finding]:
        """Analyze in-memory script data, also used by the archive engine."""
        indicators = indicators_from_script(data)
        if len(indicators) < 2:
            return []
        score = min(70, 24 + 12 * len(indicators))
        mitre = ["T1059"]
        if "encoded_execution" in indicators:
            mitre.append("T1027")
        if "persistence" in indicators:
            mitre.append("T1547.001")
        return [Finding(
            target=label, engine=self.name, threat_type="Script potencialmente peligroso",
            reason="Combinación de patrones de script: " + ", ".join(indicators),
            risk_score=score, confidence=52, severity=severity_from_score(score),
            evidence_group="script_behavior", mitre_techniques=tuple(mitre),
            details={"indicator_categories": indicators, "executed": False},
        )]

    def scan(self, target: ScanTarget) -> list[Finding]:
        """Read an eligible script or a bounded macro-enabled Office document."""
        if target.kind != "file":
            return []
        suffix = target.path.suffix.lower()
        if suffix not in _SCRIPT_SUFFIXES | _OFFICE_SUFFIXES:
            return []
        if target.path.stat().st_size > self.max_script_bytes * 8:
            raise ScanSkipped("Script/documento superior al límite de inspección")
        if suffix in _OFFICE_SUFFIXES:
            return self._scan_office(target.path)
        with target.path.open("rb") as handle:
            data = handle.read(self.max_script_bytes + 1)
        if len(data) > self.max_script_bytes:
            raise ScanSkipped("Script demasiado grande para inspección estática")
        return self.inspect_bytes(data, str(target.path))

    def _scan_office(self, path: Path) -> list[Finding]:
        """Locate VBA projects and parse them only if oletools is available."""
        try:
            with zipfile.ZipFile(path) as archive:
                entries = archive.namelist()
                if not any(name.lower().endswith("vbaproject.bin") for name in entries):
                    return []
        except (OSError, zipfile.BadZipFile) as exc:
            raise ScanSkipped(f"No se pudo abrir documento OOXML: {type(exc).__name__}") from exc
        try:
            from oletools.olevba import VBA_Parser
        except ImportError as exc:
            raise ScanSkipped("Documento con VBA: instalar oletools para inspeccionar macros") from exc
        parser = VBA_Parser(str(path))
        try:
            matched: set[str] = set()
            if parser.detect_vba_macros():
                for _, _, _, source in parser.extract_macros():
                    data = str(source).encode("utf-8", errors="replace")[:self.max_script_bytes]
                    matched.update(indicators_from_script(data))
            if len(matched) < 2:
                return []
            score = min(70, 25 + len(matched) * 12)
            return [Finding(
                target=str(path), engine=self.name,
                threat_type="Macro VBA con indicadores", reason="Categorías VBA: " + ", ".join(sorted(matched)),
                severity=severity_from_score(score), risk_score=score, confidence=50,
                mitre_techniques=("T1059.005",), evidence_group="vba_behavior",
                details={"indicator_categories": sorted(matched), "executed": False},
            )]
        except Exception as exc:
            raise ScanSkipped(f"Error al interpretar macros: {type(exc).__name__}") from exc
        finally:
            parser.close()
