"""Real per-target motor eligibility, persistence, and cancellation regressions."""
from __future__ import annotations

from pathlib import Path

from app.config import ScanConfig
from core.detection_engine import DetectionEngine
from core.models import Finding, ScanStatus, ScanTarget
from core.scanner_manager import ScannerManager
from db.database import SQLiteStore
from engines.hash_engine import HashEngine
from engines.pe_engine import PEEngine
from engines.script_engine import ScriptEngine


class SyntheticPE(PEEngine):
    """Prove magic-based PE routing without parsing unsafe PE contents."""

    name = "pe_static"

    def scan(self, target: ScanTarget) -> list[Finding]:
        """Do not parse or execute synthetic MZ fixtures."""
        return []


class ProcessLike(DetectionEngine):
    """Custom engine with explicit process eligibility."""

    name = "synthetic_process"

    def applies_to(self, target: ScanTarget, file_header: bytes | None = None) -> bool:
        """Accept only virtual process targets."""
        return target.kind == "process"

    def scan(self, target: ScanTarget) -> list[Finding]:
        """Return no synthetic signals."""
        return []


class LegacyEngine(DetectionEngine):
    """External legacy engines without applies_to retain default eligibility."""

    name = "legacy"

    def scan(self, target: ScanTarget) -> list[Finding]:
        """Return no synthetic signals."""
        return []


def test_file_coverage_distinguishes_nonapplicable_and_disguised_pe(
    tmp_path: Path,
) -> None:
    """PE is not credited for .exe non-PE and can inspect renamed MZ files."""
    root = tmp_path / "samples"
    root.mkdir()
    ordinary = root / "note.txt"
    ordinary.write_bytes(b"hello, harmless fixture")
    fakeexe = root / "fake.exe"
    fakeexe.write_bytes(b"not an executable")
    disguised = root / "renamed.dat"
    disguised.write_bytes(b"MZ\x00\x00synthetic marker only")
    script = root / "test.ps1"
    script.write_bytes(b"Write-Output 'hello'")
    store = SQLiteStore(tmp_path / "coverage.db")
    cfg = ScanConfig(database_path=store.path, max_workers=1, max_pending=2)
    manager = ScannerManager(
        cfg, store, [HashEngine(store), SyntheticPE(), ScriptEngine()],
    )
    summary = manager.run([root])
    assert summary.status is ScanStatus.COMPLETED
    assert summary.scanned_files == 4
    assert summary.finding_files == 0
    assert summary.errors == 0
    assert summary.omitted_checks == 0
    assert summary.engine_metrics["pe_static"]["checks"] == 1
    assert summary.engine_metrics["pe_static"]["not_applicable"] == 3
    assert summary.engine_metrics["pe_static"]["errors"] == 0
    assert summary.engine_metrics["script_static"]["checks"] == 1
    assert summary.engine_metrics["script_static"]["not_applicable"] == 3

    notes = {
        row["engine"]: row for row in store.get_target_engine_runs(
            summary.session_id, ordinary,
        )
    }
    assert notes["hash"]["state"] == "success"
    assert notes["pe_static"]["state"] == "not_applicable"
    assert notes["script_static"]["state"] == "not_applicable"

    actual = {
        row["engine"]: row for row in store.get_target_engine_runs(
            summary.session_id, disguised,
        )
    }
    assert actual["pe_static"]["state"] == "success"
    assert all(row["signal_count"] == 0 for row in actual.values())
    fake = {
        row["engine"]: row for row in store.get_target_engine_runs(
            summary.session_id, fakeexe,
        )
    }
    assert fake["pe_static"]["state"] == "not_applicable"
    assert str(disguised) in store.get_recent_target_paths(summary.session_id)
    with store.connection() as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM scan_target_engines WHERE session_id=?",
            (summary.session_id,),
        ).fetchone()[0] == 12


def test_process_records_do_not_claim_file_engine_coverage(
    tmp_path: Path,
) -> None:
    """Only process-compatible motors may be credited for virtual targets."""
    store = SQLiteStore(tmp_path / "system.db")
    manager = ScannerManager(
        ScanConfig(database_path=store.path, max_workers=1, max_pending=1),
        store, [HashEngine(store), ProcessLike()],
    )
    target = ScanTarget(Path("process_1234"), "process", {"pid": 1234})
    summary = manager.run([], [target])
    assert summary.status is ScanStatus.COMPLETED
    assert summary.scanned_system_targets == 1
    rows = {
        x["engine"]: x for x in store.get_target_engine_runs(
            summary.session_id, target.path,
        )
    }
    assert rows["hash"]["state"] == "not_applicable"
    assert rows["synthetic_process"]["state"] == "success"
    assert summary.engine_metrics["hash"]["checks"] == 0
    assert summary.engine_metrics["hash"]["not_applicable"] == 1


def test_legacy_engine_is_not_silently_disabled(tmp_path: Path) -> None:
    """Keep conservative support for third-party legacy engine contracts."""
    target = tmp_path / "safe.txt"
    target.write_bytes(b"safe")
    db = SQLiteStore(tmp_path / "legacy.db")
    summary = ScannerManager(
        ScanConfig(database_path=db.path, max_workers=1, max_pending=1),
        db, [LegacyEngine()],
    ).run([target])
    assert summary.engine_metrics["legacy"]["checks"] == 1
    assert db.get_target_engine_runs(
        summary.session_id, target,
    )[0]["state"] == "success"


def test_pe_magic_eligibility_is_independent_of_extension(tmp_path: Path) -> None:
    """Do not trust an .exe extension alone or ignore an MZ header in .dat."""
    engine = PEEngine()
    assert engine.applies_to(ScanTarget(tmp_path / "renamed.dat"), b"MZpayload")
    assert not engine.applies_to(ScanTarget(tmp_path / "fake.exe"), b"ordinary")
    assert not engine.applies_to(ScanTarget(tmp_path / "script.ps1"), b"hello")
    assert not engine.applies_to(ScanTarget(tmp_path / "p1", "process"), b"MZ")
