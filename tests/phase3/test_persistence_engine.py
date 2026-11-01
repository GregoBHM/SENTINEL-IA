"""Read-only persistence heuristics with synthetic Windows strings."""
from pathlib import Path

from core.models import ScanTarget
from engines.persistence_engine import PersistenceEngine, parse_command_executable


def test_extract_quoted_autorun_executable() -> None:
    """Parse a quoted launch path without running it."""
    command = '"C:\\Users\\person\\AppData\\Roaming\\svch0st.exe" /quiet'
    assert parse_command_executable(command).lower().endswith("svch0st.exe")


def test_ordinary_run_key_does_not_flag() -> None:
    """Run keys alone are not malware indicators."""
    target = ScanTarget(Path("persistence_test"), "persistence", {
        "entry": "HKCU\\Run\\Application", "command": '"C:\\Program Files\\Vendor\\app.exe"',
        "source_type": "registry"})
    assert PersistenceEngine().scan(target) == []


def test_suspicious_autorun_correlates_indicators() -> None:
    """A spoofed service name in AppData produces an ATT&CK-linked finding."""
    target = ScanTarget(Path("persistence_test"), "persistence", {
        "entry": "HKCU\\Run\\Test", "command": '"C:\\Users\\person\\AppData\\Roaming\\svch0st.exe"',
        "source_type": "registry"})
    findings = PersistenceEngine().scan(target)
    assert findings and "T1547.001" in findings[0].mitre_techniques
    assert findings[0].details["executable_path"].endswith("svch0st.exe")
