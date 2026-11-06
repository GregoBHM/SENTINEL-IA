"""Synthetic coverage review tests; no malware, network or remediation."""
from __future__ import annotations

from pathlib import Path

import pytest

from core.file_identity import FileIdentity
from core.investigation_coverage import read_investigation_coverage
from core.performance import EngineTiming
from core.report import ReportService
from db.database import SQLiteStore


def _fixture(tmp_path: Path):
    store = SQLiteStore(tmp_path / "coverage.sqlite")
    store.start_session("case")
    store.start_session("other")
    with store.connection() as conn:
        conn.execute(
            """UPDATE scan_sessions SET status='completed',scanned_files=2,
               errors=0,omitted_checks=1 WHERE id='case'"""
        )
    store.record_target_engine_runs(
        "case", tmp_path / "one.exe", "partial",
        [
            EngineTiming("hash", "success", 0.01, 80),
            EngineTiming("script_static", "skipped", 0.01, 80),
        ],
        file_identity=FileIdentity(
            str(tmp_path / "one.exe"), "limited",
            reason="Synthetic byte budget", bytes_read=40, file_size=80,
        ),
    )
    with store.connection() as conn:
        conn.execute(
            """INSERT INTO scan_archive_members(
               session_id,container_path,member_path,archive_format,
               status,reason,bytes_read,depth,checks_json)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            ("case", "fixture.zip", "fixture.zip::opaque.7z",
             "7z", "uninspected", "7z metadata only", 0, 1, "[]"),
        )
    return store


def test_coverage_review_explains_partial_results_and_is_session_scoped(tmp_path):
    store = _fixture(tmp_path)
    review = read_investigation_coverage(store, "case")
    assert review.status == "completed"
    assert review.scanned_files == 2
    assert review.checks_finished == 1
    assert review.checks_incomplete == 1
    assert review.archive_incomplete == 1
    assert review.file_identities_incomplete == 1
    assert review.has_limits
    assert "COBERTURA LIMITADA" in "\n".join(review.lines())
    assert "equipo limpio" not in "\n".join(review.lines()).lower().split("COBERTURA")[0]

    other = read_investigation_coverage(store, "other")
    assert other.scanned_files == 0
    assert other.checks_incomplete == 0
    assert other.checks_finished == 0
    assert other.has_limits  # no measurements is unknown, never clean


def test_unknown_session_fails_closed(tmp_path):
    store = _fixture(tmp_path)
    with pytest.raises(ValueError):
        read_investigation_coverage(store, "unknown")
    with pytest.raises(ValueError):
        read_investigation_coverage(store, "")


def test_coverage_is_included_in_safe_offline_html_export(tmp_path):
    store = _fixture(tmp_path)
    report = ReportService(store).export_html("case", tmp_path / "coverage.html")
    body = report.read_text(encoding="utf-8")
    assert "Alcance y limitaciones de la investigación" in body
    assert "COBERTURA LIMITADA" in body
    assert "Archivos internos inspeccionados" in body
    assert "script_static" not in body  # aggregate, no internal code details
    assert "default-src 'none'" in body
