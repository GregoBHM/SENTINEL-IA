"""Regression tests for the Windows PowerShell Python discovery probe.

These tests run on any host. They validate the probe logic and ensure that
Windows PowerShell 5.1 will not have to forward embedded Python string quotes.
They do not replace a native Windows build test.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_build_probe_uses_quote_free_python_command() -> None:
    """Keep Python -c immune to legacy PowerShell double-quote removal."""
    content = (ROOT / "build_windows.ps1").read_text(encoding="utf-8-sig")
    match = re.search(r"(?m)^\$probeCode = '([^'\r\n]+)'\s*$", content)
    assert match is not None, "Expected a single-line PowerShell probe"
    expression = match.group(1)
    assert '"' not in expression, "Quoted Python literals can break under Windows PowerShell 5.1"
    assert "sys.maxsize" in expression
    assert "sys.version_info" in expression


def test_build_probe_recognizes_current_python() -> None:
    """Execute exactly the embedded probe with the active Python interpreter."""
    content = (ROOT / "build_windows.ps1").read_text(encoding="utf-8-sig")
    match = re.search(r"(?m)^\$probeCode = '([^'\r\n]+)'\s*$", content)
    assert match is not None
    completed = subprocess.run(
        [sys.executable, "-c", match.group(1)],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    expected = int(
        sys.version_info[0] == 3
        and sys.version_info[1] >= 11
        and sys.maxsize > 2**32
    )
    assert completed.stdout.strip() == str(expected)
