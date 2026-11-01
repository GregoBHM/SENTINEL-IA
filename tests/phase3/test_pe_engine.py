"""PE heuristics are tested without real executable malware."""
from pathlib import Path

from core.models import ScanTarget
from engines.pe_engine import PEEngine, shannon_entropy
from platform_win.authenticode import verify_authenticode


def test_shannon_entropy_is_bounded() -> None:
    """Constant content has entropy 0; equal byte counts have entropy 8."""
    assert shannon_entropy(b"z" * 100) == 0.0
    assert 7.99 < shannon_entropy(bytes(range(256))) <= 8.0


def test_non_pe_files_are_not_parsed(tmp_path: Path) -> None:
    """Other file types do not reach native PE parsers."""
    txt = tmp_path / "sample.txt"
    txt.write_text("harmless")
    assert PEEngine().scan(ScanTarget(txt)) == []


def test_signature_verification_unavailable_on_non_windows(tmp_path: Path) -> None:
    """Do not claim Authenticode verification on non-Windows hosts."""
    assert verify_authenticode(tmp_path / "missing.exe").status == "unavailable"


def test_correlated_pe_indicators_with_synthetic_parser(tmp_path: Path, monkeypatch) -> None:
    """Parse mocked PE metadata to demonstrate scoring, without a binary sample."""
    from types import SimpleNamespace
    from engines import pe_engine as engine_module

    class MockSection:
        """Section with a suspicious packer name and deterministic sample data."""
        Name = b".UPX0\x00\x00\x00"
        SizeOfRawData = 8192

        def get_data(self, length: int) -> bytes:
            """Return high-entropy-like uniform bytes for safe static tests."""
            return bytes(range(256)) * (length // 256)

    class MockPE:
        """A fake pefile.PE adapter with a single suspicious import."""
        sections = [MockSection()]
        DIRECTORY_ENTRY_IMPORT = [SimpleNamespace(imports=[
            SimpleNamespace(name=b"WriteProcessMemory")])]

        def parse_data_directories(self, directories: list[int]) -> None:
            """Accept import directory request."""

        def close(self) -> None:
            """Release fake handle."""

    fake = SimpleNamespace(PE=lambda path, fast_load: MockPE(),
                           PEFormatError=ValueError,
                           DIRECTORY_ENTRY={"IMAGE_DIRECTORY_ENTRY_IMPORT": 1})
    monkeypatch.setattr(engine_module, "pefile", fake)
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ harmless test marker")
    findings = engine_module.PEEngine().scan(ScanTarget(sample))
    assert findings and findings[0].risk_score >= 35
    assert findings[0].confidence < 70
    assert "WriteProcessMemory".lower() in findings[0].details["imports_of_interest"]
