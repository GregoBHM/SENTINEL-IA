"""Optional YARA-X compatibility and archive integration on harmless fixtures."""
from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from app.config import ScanConfig, load_config_file
from core.errors import RuleLoadError, ScanSkipped
from core.models import ScanTarget, Severity
from engines.archive_engine import ArchiveEngine
from engines.yara_engine import YaraEngine
from engines.yara_x_engine import YaraXEngine


def _bundle() -> Path:
    """Return the shipped harmless synthetic rules pack."""
    return Path(__file__).parents[1] / "rules" / "bundled"


def test_opt_in_config_and_invalid_backend(tmp_path: Path) -> None:
    """Native YARA remains the default; opt-in is explicit and validated."""
    assert ScanConfig().yara_backend in ("classic", "yarax")
    with pytest.raises(ValueError):
        ScanConfig(yara_backend="both")
    config = tmp_path / "config.toml"
    config.write_text('[scanner]\nyara_backend="yarax"\n', encoding="utf-8")
    assert load_config_file(config).yara_backend == "yarax"


def test_yarax_optional_synthetic_rule_and_metadata(tmp_path: Path) -> None:
    """Match the same harmless marker without confusing a test with malware."""
    pytest.importorskip("yara_x")
    engine = YaraXEngine(_bundle())
    target = tmp_path / "sample.bin"
    target.write_bytes(b"xxONEGUARD_SYNTHETIC_TEST_SIGNATURExx")
    hits = engine.scan(ScanTarget(target))
    assert len(hits) == 1
    assert hits[0].rule_id == "OneGuard_Synthetic_Test"
    assert hits[0].severity is Severity.INFO
    assert hits[0].risk_score == 0
    assert hits[0].details["backend"] == "yarax"
    assert hits[0].details["test_only"] is True


def test_yara_and_yarax_synthetic_rule_parity(tmp_path: Path) -> None:
    """Same rules and bytes must generate the same synthetic rule IDs."""
    pytest.importorskip("yara")
    pytest.importorskip("yara_x")
    content = b"ONEGUARD_SYNTHETIC_TEST_SIGNATURE"
    path = tmp_path / "fixture.data"
    path.write_bytes(content)
    classics = YaraEngine(_bundle()).scan(ScanTarget(path))
    modern = YaraXEngine(_bundle()).scan(ScanTarget(path))
    assert {f.rule_id for f in classics} == {f.rule_id for f in modern}
    assert {f.risk_score for f in classics} == {f.risk_score for f in modern}
    assert {f.details["test_only"] for f in classics} == {
        f.details["test_only"] for f in modern
    }


def test_yarax_size_limit_and_invalid_pack(tmp_path: Path) -> None:
    """No silent fallback on unsupported packs or oversized objects."""
    pytest.importorskip("yara_x")
    engine = YaraXEngine(_bundle(), max_file_size=4)
    path = tmp_path / "oversized.bin"
    path.write_bytes(b"hello world")
    with pytest.raises(ScanSkipped) as exc:
        engine.scan(ScanTarget(path))
    assert exc.value.code == "SCAN.YARA.SIZE_LIMIT"
    bad = tmp_path / "rules"
    bad.mkdir()
    (bad / "bad.yar").write_text("not a valid rule", encoding="utf-8")
    with pytest.raises(RuleLoadError):
        YaraXEngine(bad)


def test_yarax_scans_bounded_zip_members(tmp_path: Path) -> None:
    """ZIP members also use the selected YARA backend; no hidden classic calls."""
    pytest.importorskip("yara_x")
    path = tmp_path / "harmless.zip"
    with zipfile.ZipFile(path, mode="w") as z:
        z.writestr("marker.txt", "ONEGUARD_SYNTHETIC_TEST_SIGNATURE")
    engine = ArchiveEngine(yara_engine=YaraXEngine(_bundle()))
    hits = engine.scan(ScanTarget(path))
    yara_hits = [f for f in hits if f.engine == "yara"]
    assert len(yara_hits) == 1
    assert yara_hits[0].rule_id == "OneGuard_Synthetic_Test"
    assert yara_hits[0].details["backend"] == "yarax"
    assert yara_hits[0].risk_score == 0


def test_classic_scans_bounded_zip_members(tmp_path: Path) -> None:
    """Refactoring shared archive interface must preserve classic coverage."""
    pytest.importorskip("yara")
    path = tmp_path / "harmless.zip"
    with zipfile.ZipFile(path, mode="w") as z:
        z.writestr("marker.txt", "ONEGUARD_SYNTHETIC_TEST_SIGNATURE")
    findings = ArchiveEngine(
        yara_engine=YaraEngine(_bundle())
    ).scan(ScanTarget(path))
    yara_hits = [f for f in findings if f.engine == "yara"]
    assert len(yara_hits) == 1
    assert yara_hits[0].details["backend"] == "classic"
