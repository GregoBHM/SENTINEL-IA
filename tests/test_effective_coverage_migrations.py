"""Additive database schema upgrades for old OneGuard performance records."""
from __future__ import annotations

import sqlite3
from pathlib import Path

from db.database import SQLiteStore
from core.performance import EngineTiming


def test_existing_engine_metrics_survive_new_coverage_columns(tmp_path: Path) -> None:
    """A previous build can reopen without losing a session or old metrics."""
    file = tmp_path / "old.db"
    with sqlite3.connect(file) as conn:
        conn.execute(
            "CREATE TABLE scan_sessions (id TEXT PRIMARY KEY, started_at TEXT "
            "NOT NULL, finished_at TEXT, status TEXT NOT NULL, "
            "discovered_files INTEGER NOT NULL DEFAULT 0, "
            "scanned_files INTEGER NOT NULL DEFAULT 0, "
            "finding_files INTEGER NOT NULL DEFAULT 0, "
            "errors INTEGER NOT NULL DEFAULT 0, "
            "omitted_checks INTEGER NOT NULL DEFAULT 0)"
        )
        conn.execute(
            "CREATE TABLE scan_engine_metrics ("
            "session_id TEXT NOT NULL, engine TEXT NOT NULL, "
            "checks INTEGER NOT NULL DEFAULT 0, "
            "completed INTEGER NOT NULL DEFAULT 0, "
            "skipped INTEGER NOT NULL DEFAULT 0, "
            "errors INTEGER NOT NULL DEFAULT 0, "
            "duration_seconds REAL NOT NULL DEFAULT 0, "
            "input_size_bytes INTEGER NOT NULL DEFAULT 0, "
            "signals INTEGER NOT NULL DEFAULT 0, "
            "PRIMARY KEY(session_id,engine))"
        )
        conn.execute(
            "INSERT INTO scan_sessions(id,started_at,status) "
            "VALUES('old','2026-11-01T00:00:00','completed')"
        )
        conn.execute(
            "INSERT INTO scan_engine_metrics(session_id,engine,checks,completed) "
            "VALUES('old','hash',12,12)"
        )
    store = SQLiteStore(file)
    previous = store.get_engine_metrics("old")
    assert previous[0]["checks"] == 12
    assert previous[0]["not_applicable"] == 0
    assert previous[0]["not_run"] == 0
    store.record_target_engine_runs(
        "old", Path("sample.bin"), "scanned",
        [
            EngineTiming("hash", "success", 0.1, 5),
            EngineTiming("pe_static", "not_applicable", 0.0, 0,
                         reason="No es un archivo PE"),
        ],
    )
    rows = store.get_target_engine_runs("old", Path("sample.bin"))
    assert [x["state"] for x in rows] == ["success", "not_applicable"]


def test_performance_not_applicable_and_not_run_are_not_errors() -> None:
    """An irrelevant motor invocation must not affect actual check counts."""
    from core.performance import PerformanceMonitor

    monitor = PerformanceMonitor()
    monitor.record_target(input_size_bytes=100, timings=[
        EngineTiming("pe", "not_applicable", 0, 0),
        EngineTiming("hash", "success", 0.2, 100),
        EngineTiming("persist", "not_run", 0, 0),
    ])
    rows = monitor.engine_metrics()
    assert rows["pe"]["checks"] == 0
    assert rows["pe"]["errors"] == 0
    assert rows["pe"]["not_applicable"] == 1
    assert rows["persist"]["not_run"] == 1
    assert rows["persist"]["checks"] == 0
    assert rows["hash"]["completed"] == 1
