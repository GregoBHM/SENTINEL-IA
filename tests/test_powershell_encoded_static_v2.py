"""Harmless static PowerShell fixtures; no script is ever executed."""
from __future__ import annotations

import base64
from pathlib import Path

import pytest

from core.errors import ScanSkipped
from core.models import ScanTarget
from engines.script_engine import ScriptEngine, indicators_from_script


def _encoded(script: str) -> bytes:
    return base64.b64encode(script.encode("utf-16-le"))


def test_nested_powershell_encoded_command_categories_without_execution():
    command = "Invoke-WebRequest -Uri https://invalid.example/test; Invoke-Expression 'hello'"
    encoded = _encoded(command)
    data = b"powershell.exe -EncodedCommand " + encoded
    categories = indicators_from_script(data)
    assert "encoded_execution" in categories
    assert "download" in categories
    assert "dynamic_execution" in categories
    findings = ScriptEngine().inspect_bytes(data, "synthetic.ps1")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.details["executed"] is False
    assert command not in finding.reason
    assert command not in repr(finding.details)
    assert finding.risk_score <= 70


def test_benign_encoded_command_does_not_generate_threat():
    data = b"pwsh -enc " + _encoded("Write-Output 'Hello world'")
    findings = ScriptEngine().inspect_bytes(data, "benign.ps1")
    assert findings == []
    assert indicators_from_script(data) == ["encoded_execution"]


def test_utf16le_script_static_indicators():
    raw = ("Invoke-WebRequest https://invalid.example/a; "
           "Invoke-Expression 'fixture'").encode("utf-16-le")
    assert {"download", "dynamic_execution"} <= set(indicators_from_script(raw))
    assert {"download", "dynamic_execution"} <= set(
        indicators_from_script(b"\xff\xfe" + raw)
    )


def test_malformed_and_oversized_payload_do_not_crash():
    encoded = b"A" * 12289
    malformed = b"powershell -enc " + encoded
    names = indicators_from_script(malformed)
    assert "encoded_execution" in names
    assert "download" not in names
    assert ScriptEngine().inspect_bytes(malformed, "long.ps1") == []


def test_single_file_scanner_uses_static_analysis_only(tmp_path: Path):
    file = tmp_path / "fixture.ps1"
    file.write_bytes(
        b"powershell -enc " +
        _encoded("Invoke-WebRequest https://invalid.example; Invoke-Expression 'hi'")
    )
    findings = ScriptEngine().scan(ScanTarget(file))
    assert len(findings) == 1
    assert findings[0].details.get("executed") is False


def test_archive_script_budget_is_enforced():
    engine = ScriptEngine(max_script_bytes=64)
    with pytest.raises(ScanSkipped):
        engine.inspect_bytes(b"powershell " + b"x" * 128, "archive::big.ps1")


def test_oversized_vba_project_reports_incomplete_coverage(tmp_path: Path):
    import zipfile

    path = tmp_path / "synthetic.docm"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as handle:
        handle.writestr("word/vbaProject.bin", b"x" * 9000)
    engine = ScriptEngine(max_script_bytes=8192)
    with pytest.raises(ScanSkipped, match="VBA excede"):
        engine.scan(ScanTarget(path))


def test_vba_absent_in_valid_ooxml_has_no_macro_signal(tmp_path: Path):
    import zipfile

    path = tmp_path / "document.docm"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as handle:
        handle.writestr("word/document.xml", "<document>synthetic</document>")
    assert ScriptEngine().scan(ScanTarget(path)) == []
