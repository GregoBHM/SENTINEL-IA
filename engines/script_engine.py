"""Script and macro heuristics: strings and structure only, never execution."""
from __future__ import annotations

import base64
import binascii
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

# PowerShell -EncodedCommand is typically UTF-16LE. Never execute the decoded
# command, store its plaintext, or decompress arbitrary data.
_POWERSHELL_ENCODED_COMMAND = re.compile(
    r"(?i)\b(?:powershell|pwsh)(?:\.exe)?\b[^\r\n]{0,160}?"
    r"\s-(?:encodedcommand|enc)\s+([A-Za-z0-9+/=]{16,12289})(?![A-Za-z0-9+/=])"
)
_MAX_ENCODED_COMMAND_CHARS = 8192
_MAX_DECODED_COMMAND_BYTES = 6144


def _script_text(data: bytes) -> str:
    """Decode ordinary UTF-8 or explicitly UTF-16LE Windows script content."""
    if data.startswith(b"\xff\xfe"):
        return data.decode("utf-16", errors="replace")
    if len(data) >= 8 and len(data) % 2 == 0:
        sample = data[: min(512, len(data))]
        if sample[1::2].count(0) > len(sample[1::2]) // 2:
            return data.decode("utf-16-le", errors="replace")
    return data.decode("utf-8-sig", errors="replace")


def _categories(text: str) -> set[str]:
    return {
        name for name, patterns in _COMPILED.items()
        if any(pattern.search(text) for pattern in patterns)
    }


def indicators_from_script(data: bytes) -> list[str]:
    """Identify behavioral categories from bounded static text, never execution.

    Decoding PowerShell EncodedCommand is a best-effort layer only. Unsupported
    formats and non-script encodings are NOT assumed clean, and the original
    encoded/decoded content is never included in the returned result.
    """
    text = _script_text(data)
    detected = _categories(text)
    # Limit interpretation to the first 64 KiB of script and four small tokens.
    for match in list(_POWERSHELL_ENCODED_COMMAND.finditer(text[:65536]))[:4]:
        token = match.group(1)
        if len(token) > _MAX_ENCODED_COMMAND_CHARS:
            continue
        try:
            decoded = base64.b64decode(token, validate=True)
            if (len(decoded) > _MAX_DECODED_COMMAND_BYTES
                    or len(decoded) % 2 != 0 or not decoded):
                continue
            command = decoded.decode("utf-16-le", errors="strict")
        except (ValueError, UnicodeError, binascii.Error):
            continue
        if any(ord(char) < 32 and char not in "\r\n\t" for char in command):
            continue
        # Intentionally no recursive decoding: bounded, low-confidence hints.
        detected.update(_categories(command))
    return [name for name in _FAMILIES if name in detected]


class ScriptEngine(DetectionEngine):
    """Look for clusters of suspicious scripting constructs and macro indicators."""

    name = "script_static"

    def __init__(self, *, max_script_bytes: int = 2 * 1024 * 1024) -> None:
        """Limit memory consumed per input."""
        self.max_script_bytes = max_script_bytes

    def inspect_bytes(self, data: bytes, label: str) -> list[Finding]:
        """Analyze in-memory script data, also used by the archive engine."""
        if len(data) > self.max_script_bytes:
            raise ScanSkipped("Script no inspeccionado: excede el presupuesto estático")
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

    def applies_to(self, target: ScanTarget, file_header: bytes | None = None) -> bool:
        """Script and macro paths are classified by supported extensions."""
        return (
            target.kind == "file"
            and target.path.suffix.lower() in _SCRIPT_SUFFIXES | _OFFICE_SUFFIXES
        )

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
