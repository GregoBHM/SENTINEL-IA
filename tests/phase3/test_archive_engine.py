"""Safe ZIP fixtures exercise nested detection, bounds and coverage gaps."""
import hashlib
import io
import zipfile
from pathlib import Path

from core.models import ScanTarget
from db.database import SQLiteStore
from engines.archive_engine import ArchiveEngine


def make_zip(entries: dict[str, bytes]) -> bytes:
    """Build a harmless in-memory archive."""
    handle = io.BytesIO()
    with zipfile.ZipFile(handle, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return handle.getvalue()


def test_nested_zip_hash_signature(store: SQLiteStore, tmp_path: Path) -> None:
    """Find a reviewed synthetic digest in a nested ZIP without extracting."""
    marker = b"SYNTHETIC_FIXTURE_NOT_MALWARE_PHASE3"
    digest = hashlib.sha256(marker).hexdigest()
    store.add_hash_signature(digest, "fixture", "Laboratory", "Test digest", 90)
    nested = make_zip({"inside.exe": marker})
    source = tmp_path / "package.zip"
    source.write_bytes(make_zip({"nested.zip": nested}))
    findings = ArchiveEngine(store).scan(ScanTarget(source))
    hit = [x for x in findings if x.engine == "hash"]
    assert len(hit) == 1
    assert hit[0].sha256 == digest
    assert "nested.zip::inside.exe" in hit[0].target


def test_double_extension_does_not_become_critical(tmp_path: Path) -> None:
    """Misleading archive filename is a weak indicator, not a stealer verdict."""
    source = tmp_path / "archive.zip"
    source.write_bytes(make_zip({"invoice.pdf.exe": b"harmless"}))
    findings = ArchiveEngine().scan(ScanTarget(source))
    assert any(x.rule_id == "double_extension" for x in findings)
    assert all(x.risk_score < 40 for x in findings)


def test_large_member_marked_uninspected(tmp_path: Path) -> None:
    """Do not read oversized uncompressed members as if clean."""
    source = tmp_path / "oversized.zip"
    source.write_bytes(make_zip({"big.txt": b"x" * 128}))
    engine = ArchiveEngine(max_total_bytes=8192, max_member_bytes=32)
    findings = engine.scan(ScanTarget(source))
    assert any(x.rule_id == "size_limit" for x in findings)
    assert all(x.risk_score == 0 for x in findings)


def test_entry_with_dotdot_detected_without_extraction(tmp_path: Path) -> None:
    """Zip-slip shaped entry is signaled and never written outside container."""
    source = tmp_path / "unsafe.zip"
    source.write_bytes(make_zip({"../outside.ps1": b"Write-Host 1"}))
    findings = ArchiveEngine().scan(ScanTarget(source))
    assert any(x.rule_id == "unsafe_path" for x in findings)
    assert not (tmp_path / "outside.ps1").exists()


def test_archive_embedded_script_heuristics(tmp_path: Path) -> None:
    """Analyze scripts inside ZIP without staging scripts on disk."""
    source = tmp_path / "scripts.zip"
    source.write_bytes(make_zip({"job.ps1": b'Invoke-Expression("test"); DownloadString("abc")'}))
    findings = ArchiveEngine().scan(ScanTarget(source))
    assert any(x.engine == "script_static" for x in findings)
