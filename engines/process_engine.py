"""Read-only process/network inventory; does not inspect user credentials."""
from __future__ import annotations

import os
from pathlib import Path

from core.aggregator import severity_from_score
from core.detection_engine import DetectionEngine
from core.heuristics import risky_user_location, system_filename_spoof
from core.models import Finding, ScanTarget
from core.system_identity import SystemObservation, observe_process_identity
from platform_win.authenticode import verify_authenticode

try:
    import psutil
except ImportError:
    psutil = None

_SYSTEM_NAMES = {"svchost.exe", "lsass.exe", "services.exe", "winlogon.exe",
                 "csrss.exe", "smss.exe", "spoolsv.exe"}


class ProcessEngine(DetectionEngine):
    """Correlate process masquerading, executable paths and connections."""

    name = "process_network"

    def enumerate_targets(self, limit: int = 20000) -> list[ScanTarget]:
        """Snapshot process identities; excluded/inaccessible processes stay unknown."""
        if psutil is None:
            return []
        result = []
        for process in psutil.process_iter(attrs=["pid", "name", "exe", "create_time"]):
            if len(result) >= limit:
                break
            try:
                info = process.info
                if info.get("pid") is not None:
                    pid = int(info["pid"])
                    result.append(ScanTarget(Path(f"process_{pid}"), "process", {
                        "pid": pid, "create_time": info.get("create_time"),
                    }))
            except (psutil.Error, ValueError, TypeError):
                continue
        return result

    def applies_to(self, target: ScanTarget, file_header: bytes | None = None) -> bool:
        """This engine inspects process inventory records, not file paths."""
        return target.kind == "process"

    def scan_with_observation(
        self, target: ScanTarget
    ) -> tuple[list[Finding], SystemObservation]:
        """Collect a PID + birth-time verified snapshot before analysis.

        Stale or inaccessible identities are incomplete coverage, not benign
        processes, and never become inputs for process/autorun correlation.
        """
        observation = observe_process_identity(target, psutil)
        if observation.status != "verified":
            return [], observation
        return self.scan(target), observation

    def scan(self, target: ScanTarget) -> list[Finding]:
        """Check PID reuse, path authenticity and low-confidence network indicators."""
        if target.kind != "process" or psutil is None:
            return []
        try:
            proc = psutil.Process(int(target.metadata["pid"]))
            start = target.metadata.get("create_time")
            if start is None or abs(proc.create_time() - float(start)) > 0.01:
                return []  # PID reused since discovery
            name = proc.name().lower()
            path = proc.exe()
            if not path:
                return []
        except (psutil.Error, OSError, ValueError, KeyError):
            return []
        signals = []
        score = 0
        if system_filename_spoof(name):
            signals.append("nombre de proceso que imita un binario de Windows")
            score += 32
        if name in _SYSTEM_NAMES and risky_user_location(path):
            signals.append("nombre de servicio Windows ejecutándose desde directorio de usuario")
            score += 32
        if risky_user_location(path):
            score += 8
        # A connection is context only: ports/IPs are not malware indicators.
        # Keep only counts, never log destination IPs or user browsing history.
        established_remote = 0
        if signals:
            try:
                for conn in proc.net_connections(kind="inet")[:2048]:
                    if conn.raddr and conn.status == "ESTABLISHED":
                        established_remote += 1
            except (psutil.Error, OSError, AttributeError):
                pass
        signature = verify_authenticode(Path(path)) if os.name == "nt" else None
        module_findings = self._inspect_loaded_modules(proc, path, name, signature)
        if not signals:
            return module_findings
        if signature is not None and signature.status == "invalid_or_untrusted":
            score += 10
        score = min(70, score)
        return module_findings + [Finding(
            target=str(target.path), engine=self.name, threat_type="Proceso con identidad anómala",
            reason="; ".join(signals), severity=severity_from_score(score),
            risk_score=score, confidence=56, evidence_group="process_masquerade",
            mitre_techniques=("T1036.005",),
            details={"pid": proc.pid, "executable_path": path,
                     "process_start": start, "authenticode": signature.status if signature else "unavailable",
                     "established_remote_connections": established_remote,
                     "network_inspection": "Conexión no equivale a exfiltración; sin monitoreo histórico."},
        )]

    def _inspect_loaded_modules(self, proc: object, executable: str, name: str,
                                signature: object) -> list[Finding]:
        """Flag user-writable unsigned DLL inside a signed Windows service image.

        This is a possible DLL side-loading indicator, not proof of hijacking.
        """
        if os.name != "nt" or name not in _SYSTEM_NAMES:
            return []
        windows_root = os.environ.get("SystemRoot", "C:\\Windows").lower().rstrip("\\")
        if not executable.lower().startswith(windows_root + "\\system32\\"):
            return []
        if signature is None or signature.status != "valid":
            return []
        try:
            paths = [mapping.path for mapping in proc.memory_maps(grouped=False)[:512]]
        except (psutil.Error, OSError, AttributeError):
            return []
        results = []
        for module in dict.fromkeys(paths):
            if len(results) >= 4:
                break
            if not module.lower().endswith(".dll") or not risky_user_location(module):
                continue
            trust = verify_authenticode(Path(module))
            if trust.status not in {"unsigned", "invalid_or_untrusted"}:
                continue
            results.append(Finding(
                target=f"process_{proc.pid}", engine=self.name,
                threat_type="Posible carga anómala de DLL",
                reason="Proceso firmado de carpeta Windows cargó DLL no confiable desde ubicación de usuario",
                severity=severity_from_score(43), risk_score=43, confidence=42,
                evidence_group="dll_sideload", mitre_techniques=("T1574.002",),
                details={"pid": proc.pid, "executable_path": executable,
                         "module_path": module, "module_authenticode": trust.status,
                         "publisher_verified": False},
            ))
        return results
