"""Windows persistence inspection: Run/RunOnce, Startup, services and tasks.

All probes read metadata; no registry writes, service stops or scheduled-task changes.
"""
from __future__ import annotations

import json
import hashlib
import os
import re
import subprocess
from pathlib import Path

from core.aggregator import severity_from_score
from core.detection_engine import DetectionEngine
from core.heuristics import has_misleading_extension, risky_user_location, system_filename_spoof
from core.models import Finding, ScanTarget

try:
    import winreg
except ImportError:
    winreg = None

_REG_PATHS = (r"Software\Microsoft\Windows\CurrentVersion\Run",
              r"Software\Microsoft\Windows\CurrentVersion\RunOnce")
_EXECUTABLE = re.compile(r'(?i)(?:"([^"\r\n]+\.(?:exe|dll|scr|bat|cmd|ps1|vbs|js))"|'
                         r'([a-z]:\\[^\r\n"<>|]+?\.(?:exe|dll|scr|bat|cmd|ps1|vbs|js)))')


def parse_command_executable(command: str) -> str:
    """Extract a likely executable path for correlation (never execute it)."""
    expanded = os.path.expandvars(command.strip())
    match = _EXECUTABLE.search(expanded)
    if match:
        return (match.group(1) or match.group(2)).strip()
    return expanded.split(maxsplit=1)[0].strip('"') if expanded else ""


class PersistenceEngine(DetectionEngine):
    """Enumerate autoruns and report suspicious combinations without changing them."""

    name = "persistence"

    def enumerate_targets(self, *, task_timeout: int = 20) -> list[ScanTarget]:
        """Snapshot supported Windows persistence locations for read-only analysis."""
        if os.name != "nt" or winreg is None:
            return []
        targets: list[ScanTarget] = []
        views = [getattr(winreg, "KEY_WOW64_64KEY", 0), getattr(winreg, "KEY_WOW64_32KEY", 0)]
        seen: set[str] = set()
        for hive, hive_name in ((winreg.HKEY_CURRENT_USER, "HKCU"),
                                (winreg.HKEY_LOCAL_MACHINE, "HKLM")):
            for view in views:
                for key_name in _REG_PATHS:
                    try:
                        with winreg.OpenKey(hive, key_name, 0, winreg.KEY_READ | view) as key:
                            idx = 0
                            while True:
                                try:
                                    name, value, _ = winreg.EnumValue(key, idx)
                                except OSError:
                                    break
                                idx += 1
                                identifier = f"{hive_name}\\{key_name}\\{name}"
                                if identifier in seen or not isinstance(value, str):
                                    continue
                                seen.add(identifier)
                                targets.append(ScanTarget(Path(f"persistence_{len(targets)}"),
                                    "persistence", {"entry": identifier, "command": value,
                                                    "source_type": "registry"}))
                    except (OSError, PermissionError):
                        continue
        for env, suffix in (("APPDATA", "Microsoft/Windows/Start Menu/Programs/Startup"),
                            ("PROGRAMDATA", "Microsoft/Windows/Start Menu/Programs/Startup")):
            root = os.environ.get(env)
            if not root:
                continue
            folder = Path(root) / suffix
            try:
                for file in folder.iterdir():
                    if file.is_symlink() or not file.is_file():
                        continue
                    targets.append(ScanTarget(Path(f"persistence_{len(targets)}"), "persistence",
                        {"entry": str(file), "command": str(file), "source_type": "startup"}))
            except (OSError, PermissionError):
                continue
        # Service ImagePath is a registry value; start mode/type must be known.
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"SYSTEM\CurrentControlSet\Services", 0, winreg.KEY_READ) as services:
                count, _, _ = winreg.QueryInfoKey(services)
                for i in range(min(count, 20000)):
                    try:
                        name = winreg.EnumKey(services, i)
                        with winreg.OpenKey(services, name, 0, winreg.KEY_READ) as service:
                            command = winreg.QueryValueEx(service, "ImagePath")[0]
                            service_type = winreg.QueryValueEx(service, "Type")[0]
                        if not isinstance(command, str) or not (service_type & 0x33):
                            continue
                        targets.append(ScanTarget(Path(f"persistence_{len(targets)}"), "persistence",
                            {"entry": f"HKLM\\SYSTEM\\CurrentControlSet\\Services\\{name}",
                             "command": command, "source_type": "service"}))
                    except (OSError, PermissionError):
                        continue
        except (OSError, PermissionError):
            pass
        # PowerShell is invoked with fixed arguments, with no untrusted interpolation.
        # Its JSON output is bounded and is not persisted in full.
        script = ('Get-ScheduledTask | ForEach-Object { '
                  '[pscustomobject]@{ Name=($_.TaskPath + $_.TaskName); '
                  'Actions=@($_.Actions | ForEach-Object { $_.Execute + " " + $_.Arguments }) } '
                  '} | ConvertTo-Json -Depth 5 -Compress')
        try:
            completed = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, timeout=task_timeout, check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if completed.returncode == 0 and len(completed.stdout) <= 8 * 1024 * 1024:
                payload = json.loads(completed.stdout.decode("utf-8-sig", errors="replace"))
                for item in ([payload] if isinstance(payload, dict) else payload or []):
                    if not isinstance(item, dict):
                        continue
                    for command in item.get("Actions", [])[:10]:
                        if isinstance(command, str):
                            targets.append(ScanTarget(Path(f"persistence_{len(targets)}"),
                                "persistence", {"entry": str(item.get("Name", "Task")),
                                                "command": command, "source_type": "task"}))
        except (OSError, subprocess.TimeoutExpired, ValueError, TypeError):
            pass
        return targets

    def scan(self, target: ScanTarget) -> list[Finding]:
        """Identify suspicious path and masquerading combinations in autostarts."""
        if target.kind != "persistence":
            return []
        command = str(target.metadata.get("command") or "")[:4096]
        executable = parse_command_executable(command)
        source_type = str(target.metadata.get("source_type", "unknown"))
        if not executable:
            return []
        factors = []
        score = 0
        if risky_user_location(executable):
            factors.append("ejecutable en ubicación modificable por usuario")
            score += 24
        if system_filename_spoof(executable):
            factors.append("nombre que suplanta un componente de Windows")
            score += 26
        if has_misleading_extension(executable):
            factors.append("doble extensión engañosa")
            score += 23
        # Startup entries on their own are normal. Require multiple indicators.
        if len(factors) < 2:
            return []
        score = min(score, 70)
        technique = {"registry": "T1547.001", "startup": "T1547.001",
                     "task": "T1053.005", "service": "T1543.003"}.get(source_type, "T1547")
        return [Finding(
            target=str(target.metadata.get("entry", target.path)), engine=self.name,
            threat_type="Persistencia potencialmente maliciosa", reason="; ".join(factors),
            severity=severity_from_score(score), risk_score=score, confidence=58,
            evidence_group="autorun", mitre_techniques=(technique,),
            details={"source_type": source_type, "executable_path": executable,
                     "action": "investigate_only", "source_entry": str(target.metadata.get("entry", "")),
                     "command_sha256": hashlib.sha256(command.encode("utf-8")).hexdigest()},
        )]
