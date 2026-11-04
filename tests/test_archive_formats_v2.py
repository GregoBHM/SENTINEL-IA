"""Benign archive magic routing and member-level coverage regression."""
from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from app.config import ScanConfig
from core.file_formats import identify_archive
from core.models import ScanStatus, ScanTarget
from core.scanner_manager import ScannerManager
from db.database import SQLiteStore
from engines.archive_engine import ArchiveEngine


def make_zip(entries: dict[str, bytes]) -> bytes:
    """Create an in-memory, harmless container without disk extraction."""
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as handle:
        for path, payload in entries.items():
            handle.writestr(path, payload)
    return stream.getvalue()


def test_magic_precedes_suffix_and_supports_renamed_containers() -> None:
    """ZIP, RAR4/5 and 7z signatures route without trusting the extension."""
    assert identify_archive(b"PK\x03\x04payload", "hidden.dat").kind == "zip"
    assert identify_archive(b"PK\x05\x06", "empty.bin").kind == "zip"
    assert identify_archive(b"Rar!\x1a\x07\x00rest", "fake.zip").kind == "rar"
    assert identify_archive(b"Rar!\x1a\x07\x01\x00rest", "fake.zip").kind == "rar"
    assert identify_archive(b"7z\xbc\xaf\x27\x1c", "fake.zip").kind == "7z"
    assert identify_archive(b"invalid", "broken.zip").source == "extension"
    assert identify_archive(b"invalid", "ordinary.txt") is None


def test_renamed_zip_and_nested_renamed_zip_have_real_member_rows(
    tmp_path: Path,
) -> None:
    """Data-signature routing must reach nested contents, not just outer labels."""
    inner = make_zip({"payload.txt": b"ordinary harmless text"})
    source = tmp_path / "renamed.dat"
    source.write_bytes(make_zip({
        "doc.bin": b"safe",
        "nested.unknown": inner,
    }))
    engine = ArchiveEngine()
    assert engine.applies_to(ScanTarget(source), source.read_bytes()[:8])
    findings, members = engine.scan_with_coverage(ScanTarget(source))
    assert not any(item.details.get("limitation") for item in findings)
    by_path = {row.member_path: row for row in members}
    assert by_path[str(source)].archive_format == "zip"
    assert by_path[str(source)].status == "inspected"
    assert by_path[str(source) + "::doc.bin"].status == "inspected"
    assert "sha256" in by_path[str(source) + "::doc.bin"].checks
    assert by_path[str(source) + "::nested.unknown"].archive_format == "zip"
    assert by_path[str(source) + "::nested.unknown::payload.txt"].status == "inspected"


def test_oversized_member_is_uninspected_not_a_malware_hit(tmp_path: Path) -> None:
    """Container and child must visibly record skipped coverage."""
    source = tmp_path / "limits.zip"
    source.write_bytes(make_zip({"large.txt": b"x" * 300, "safe.txt": b"ok"}))
    engine = ArchiveEngine(max_member_bytes=64, max_total_bytes=4096)
    findings, members = engine.scan_with_coverage(ScanTarget(source))
    by_path = {row.member_path: row for row in members}
    assert by_path[str(source)].status == "partial"
    assert by_path[str(source) + "::large.txt"].status == "uninspected"
    assert by_path[str(source) + "::safe.txt"].status == "inspected"
    assert all(f.risk_score == 0 for f in findings)


def test_invalid_zip_extension_is_explicitly_partial(tmp_path: Path) -> None:
    """A misleading extension alone must not count as inspected contents."""
    source = tmp_path / "corrupt.zip"
    source.write_bytes(b"this is not a ZIP")
    findings, members = ArchiveEngine().scan_with_coverage(ScanTarget(source))
    assert any(f.rule_id == "invalid_zip" for f in findings)
    assert any(m.status == "partial" for m in members)
    assert not any(m.status == "inspected" for m in members)


def test_member_records_are_persisted_without_changing_threat_counts(
    tmp_path: Path,
) -> None:
    """SQLite keeps member coverage and does not treat omissions as malware."""
    archive = tmp_path / "sample.dat"
    archive.write_bytes(make_zip({"safe.txt": b"sample", "large.bin": b"x" * 300}))
    store = SQLiteStore(tmp_path / "history.db")
    scanner = ScannerManager(
        ScanConfig(database_path=store.path, max_workers=1, max_pending=2),
        store, [ArchiveEngine(max_member_bytes=64, max_total_bytes=4096)],
    )
    summary = scanner.run([archive])
    assert summary.status is ScanStatus.COMPLETED
    assert summary.finding_files == 0
    assert summary.errors == 0
    assert summary.engine_metrics["archive"]["signals"] == 0
    assert summary.omitted_checks == 1  # One grouped warning per partial archive.
    with store.connection() as conn:
        row = conn.execute(
            "SELECT event_code,params_json FROM scan_coverage "
            "WHERE session_id=? AND engine='archive'",
            (summary.session_id,),
        ).fetchone()
    assert row["event_code"] == "SCAN.ARCHIVE.PARTIAL"
    assert '"uninspected_members": 1' in row["params_json"]
    found = store.get_archive_members(summary.session_id, archive)
    states = {m["member_path"]: m["status"] for m in found}
    assert states[str(archive)] == "partial"
    assert states[str(archive) + "::large.bin"] == "uninspected"
    assert states[str(archive) + "::safe.txt"] == "inspected"
    assert "sha256" in next(
        m["checks"] for m in found if m["member_path"].endswith("safe.txt")
    )
    with store.connection() as conn:
        row = conn.execute(
            "SELECT status FROM scan_targets WHERE session_id=?",
            (summary.session_id,),
        ).fetchone()
    assert row["status"] == "partial"


def test_parallel_archives_do_not_share_member_records(tmp_path: Path) -> None:
    """Context-local collection must not leak members across scanner workers."""
    folder = tmp_path / "samples"
    folder.mkdir()
    for number in range(6):
        (folder / f"archive-{number}.zip").write_bytes(
            make_zip({f"only-{number}.txt": b"benign"})
        )
    store = SQLiteStore(tmp_path / "parallel.db")
    result = ScannerManager(
        ScanConfig(database_path=store.path, max_workers=3, max_pending=6),
        store, [ArchiveEngine()],
    ).run([folder])
    assert result.errors == 0
    for number in range(6):
        archive = folder / f"archive-{number}.zip"
        members = store.get_archive_members(result.session_id, archive)
        assert len(members) == 2
        assert any(m["member_path"].endswith(f"only-{number}.txt") for m in members)
        assert not any(
            m["member_path"].endswith(f"only-{other}.txt")
            for m in members for other in range(6) if other != number
        )


def test_7z_metadata_never_claims_payload_inspection(tmp_path: Path) -> None:
    """A 7z inventory remains explicitly uninspected without isolated decoding."""
    py7zr = pytest.importorskip("py7zr")
    output = io.BytesIO()
    with py7zr.SevenZipFile(output, "w") as archive:
        archive.writestr("harmless content", "fixture.txt")
    source = tmp_path / "renamed.bin"
    source.write_bytes(output.getvalue())
    findings, members = ArchiveEngine().scan_with_coverage(ScanTarget(source))
    assert any(f.rule_id == "seven_zip_pending" for f in findings)
    assert any(m.member_path.endswith("fixture.txt") and m.status == "uninspected"
               for m in members)
    assert any(m.member_path == str(source) and m.status == "partial"
               for m in members)
