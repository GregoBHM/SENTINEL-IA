"""Bounded PE/COFF static analysis. No files are launched or modified."""
from __future__ import annotations

import math
from collections import Counter
from pathlib import Path

from core.aggregator import severity_from_score
from core.detection_engine import DetectionEngine
from core.errors import ScanSkipped
from core.heuristics import risky_user_location, system_filename_spoof
from core.models import Finding, ScanTarget
from platform_win.authenticode import SignatureResult, verify_authenticode

try:
    import pefile
except ImportError:  # dependency may be missing on the build host
    pefile = None

_PE_SUFFIXES = {".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl"}
_INJECTION_IMPORTS = {"virtualallocex", "writeprocessmemory", "createremotethread",
                      "ntwritevirtualmemory", "queueuserapc"}
_KEYBOARD_IMPORTS = {"setwindowshookexa", "setwindowshookexw", "getasynckeystate"}
_WEIRD_SECTIONS = {".upx0", ".upx1", ".aspack", ".themida", ".vmp0", ".vmp1"}


def shannon_entropy(data: bytes) -> float:
    """Compute sample entropy (0..8 bits per byte)."""
    if not data:
        return 0.0
    frequencies = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length)
                for count in frequencies.values())


class PEEngine(DetectionEngine):
    """Report correlated PE anomalies, not unproven malware family names."""

    name = "pe_static"

    def __init__(self, *, max_file_size: int = 128 * 1024 * 1024) -> None:
        """Set an upper bound on PE parsing and sampled section buffers."""
        self.max_file_size = max_file_size

    def scan(self, target: ScanTarget) -> list[Finding]:
        """Inspect selected PE-like files and Authenticode trust status."""
        if target.kind != "file" or target.path.suffix.lower() not in _PE_SUFFIXES:
            return []
        if pefile is None:
            raise ScanSkipped("Análisis PE requiere instalar pefile")
        if target.path.stat().st_size > self.max_file_size:
            raise ScanSkipped("Archivo PE excede el tamaño máximo")
        try:
            pe = pefile.PE(str(target.path), fast_load=True)
        except pefile.PEFormatError:
            return []
        try:
            return self._evaluate(pe, str(target.path), verify_authenticode(target.path))
        finally:
            pe.close()

    def inspect_bytes(self, data: bytes, label: str) -> list[Finding]:
        """Inspect an embedded PE from an archive without writing it to disk."""
        if pefile is None:
            raise ScanSkipped("Análisis PE de archivo interno requiere pefile")
        if len(data) > self.max_file_size:
            raise ScanSkipped("PE interno excede el límite")
        try:
            pe = pefile.PE(data=data, fast_load=True)
        except pefile.PEFormatError:
            return []
        try:
            # Authenticode verification requires an on-disk object on Windows.
            return self._evaluate(pe, label, SignatureResult("unavailable"))
        finally:
            pe.close()

    def _evaluate(self, pe: object, label: str,
                  signature: SignatureResult) -> list[Finding]:
        """Derive a conservative verdict from bounded, independent PE signals."""
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]
        ])
        imports = set()
        for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            for entry in descriptor.imports:
                if entry.name:
                    imports.add(entry.name.decode("ascii", errors="replace").lower())
        high_entropy = []
        strange_sections = []
        size_anomalies = []
        for section in pe.sections[:96]:
            raw_name = section.Name.split(b"\x00", 1)[0].decode("ascii", errors="replace")
            raw_size = max(0, int(section.SizeOfRawData))
            size = min(raw_size, 1024 * 1024)
            entropy = shannon_entropy(section.get_data(length=size))
            if entropy >= 7.35 and size >= 1024:
                high_entropy.append({"section": raw_name, "entropy": round(entropy, 2)})
            if raw_name.lower() in _WEIRD_SECTIONS:
                strange_sections.append(raw_name)
            virtual_size = max(0, int(getattr(section, "Misc_VirtualSize", raw_size)))
            if raw_size > 10 * max(1, virtual_size) and raw_size > 1024 * 1024:
                size_anomalies.append(raw_name)
        indicators = []
        score = 0
        if high_entropy:
            indicators.append("sección con entropía elevada")
            score += 20
        if strange_sections:
            indicators.append("nombre de sección asociado a empaquetadores")
            score += 18
        if size_anomalies:
            indicators.append("tamaño raw / virtual de sección anómalo")
            score += 12
        if imports & _INJECTION_IMPORTS:
            indicators.append("API relacionada con manipulación de memoria de otros procesos")
            score += 23
        if imports & _KEYBOARD_IMPORTS:
            indicators.append("API de captura/consulta de teclado")
            score += 19
        if risky_user_location(label):
            indicators.append("ubicación modificable por usuario")
            score += 12
        if system_filename_spoof(label):
            indicators.append("nombre similar al de un componente de Windows")
            score += 18
        if signature.status == "invalid_or_untrusted":
            indicators.append("firma Authenticode no válida o no confiable")
            score += 12
        independent_signals = sum(bool(v) for v in (
            high_entropy or strange_sections or size_anomalies,
            imports & (_INJECTION_IMPORTS | _KEYBOARD_IMPORTS),
            risky_user_location(label) or system_filename_spoof(label),
            signature.status == "invalid_or_untrusted",
        ))
        if independent_signals < 2 or score < 35:
            return []
        score = min(75, score)
        return [Finding(
            target=label, engine=self.name, threat_type="Anomalías PE",
            reason="Indicadores estáticos correlacionados: " + "; ".join(indicators),
            risk_score=score, severity=severity_from_score(score), confidence=50,
            evidence_group="pe_anomaly", mitre_techniques=("T1027",),
            details={"imports_of_interest": sorted(imports & (_INJECTION_IMPORTS | _KEYBOARD_IMPORTS)),
                     "high_entropy_sections": high_entropy, "unusual_sections": strange_sections,
                     "size_anomalies": size_anomalies,
                     "authenticode": signature.status, "publisher_verified": False,
                     "note": "Los indicadores PE no confirman infección ni identidad de autor."},
        )]
