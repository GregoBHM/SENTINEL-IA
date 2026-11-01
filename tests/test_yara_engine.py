"""YARA native integration is checked only when yara-python is available."""
from pathlib import Path

import pytest

from core.errors import RuleLoadError, ScanSkipped
from core.models import ScanTarget, Severity
from engines.yara_engine import YaraEngine


def test_yara_matches_synthetic_marker(tmp_path: Path) -> None:
    """Match a harmless marker without executing its contents."""
    pytest.importorskip(
        "yara", reason="Native yara-python dependency not installed in test environment"
    )
    rules_dir = Path(__file__).parents[1] / "rules" / "bundled"
    engine = YaraEngine(rules_dir)
    file = tmp_path / "test.txt"
    file.write_text("ONEGUARD_SYNTHETIC_TEST_SIGNATURE", encoding="utf-8")
    found = engine.scan(ScanTarget(file))
    assert len(found) == 1
    assert found[0].severity == Severity.INFO
    assert found[0].details["test_only"] is True


def test_yara_size_cap(tmp_path: Path) -> None:
    """Enforce the file cap rather than scanning unbounded content."""
    pytest.importorskip("yara")
    engine = YaraEngine(Path(__file__).parents[1] / "rules" / "bundled", max_file_size=1)
    file = tmp_path / "too-large.txt"
    file.write_bytes(b"123456")
    with pytest.raises(ScanSkipped):
        engine.scan(ScanTarget(file))


def test_invalid_rules_report_error(tmp_path: Path) -> None:
    """Invalid packs must fail explicitly rather than silently going missing."""
    pytest.importorskip("yara")
    (tmp_path / "broken.yar").write_text("this is not yara", encoding="utf-8")
    with pytest.raises(RuleLoadError):
        YaraEngine(tmp_path)
