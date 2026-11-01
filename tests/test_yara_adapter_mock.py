"""Independent YARA adapter contract tests without a native yara install."""
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.models import ScanTarget, Severity
from engines import yara_engine


class FakeCompiledRules:
    """Mock the native compiled rules object without inspecting malware."""

    def match(self, *, filepath: str, timeout: int) -> list[object]:
        """Emit a deterministic synthetic rule match."""
        assert Path(filepath).is_file()
        assert timeout == 20
        return [SimpleNamespace(
            rule="SyntheticRule", namespace="ruleset_1", tags=["fixture"],
            meta={"risk_score": 70, "confidence": 65,
                  "threat_type": "Prueba sintética", "description": "Solo un fixture",
                  "mitre": "T1059"},
        )]


class FakeYara:
    """Mock the native compile function and its filepaths argument."""

    @staticmethod
    def compile(*, filepaths: dict[str, str]) -> FakeCompiledRules:
        """Ensure YARA files are discovered and namespaced."""
        assert filepaths
        return FakeCompiledRules()


def test_rule_adapter_maps_metadata(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Convert native-style matches to traceable Finding fields."""
    monkeypatch.setattr(yara_engine, "yara", FakeYara())
    rule_dir = tmp_path / "rules"
    rule_dir.mkdir()
    (rule_dir / "fixture.yar").write_text("rule fixture {}")
    engine = yara_engine.YaraEngine(rule_dir)
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"This is harmless")
    findings = engine.scan(ScanTarget(sample))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "SyntheticRule"
    assert finding.severity == Severity.HIGH
    assert finding.risk_score == 70
    assert finding.mitre_techniques == ("T1059",)
    assert finding.details["namespace"] == "ruleset_1"
