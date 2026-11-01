"""Synthetic script patterns; nothing is executed."""
from pathlib import Path

from core.models import ScanTarget
from engines.script_engine import ScriptEngine, indicators_from_script


def test_ordinary_admin_script_not_malware(tmp_path: Path) -> None:
    """Single PowerShell keyword is insufficient to create a finding."""
    source = tmp_path / "admin.ps1"
    source.write_text('Write-Host "maintenance"\n$encoded = "base64"', encoding="utf-8")
    assert ScriptEngine().scan(ScanTarget(source)) == []


def test_synthetic_download_and_dynamic_execution(tmp_path: Path) -> None:
    """Two independent indicator families create an explained detection."""
    source = tmp_path / "synthetic.ps1"
    source.write_text('Invoke-Expression ("test"); # DownloadString("example")', encoding="utf-8")
    findings = ScriptEngine().scan(ScanTarget(source))
    assert len(findings) == 1
    assert set(findings[0].details["indicator_categories"]) == {"download", "dynamic_execution"}
    assert findings[0].confidence < 80


def test_script_bytes_not_leaked_in_evidence() -> None:
    """Raw script source cannot be copied to result details."""
    data = b'Invoke-Expression("secret-password-synthetic"); DownloadString("test")'
    findings = ScriptEngine().inspect_bytes(data, "memory.ps1")
    assert findings
    assert "secret-password-synthetic" not in str(findings[0])


def test_persistence_obfuscation_categories() -> None:
    """Recognize multiple technical categories without malware family attribution."""
    categories = indicators_from_script(
        b'powershell -EncodedCommand AAA; New-Service -Name test'
    )
    assert "encoded_execution" in categories and "persistence" in categories
