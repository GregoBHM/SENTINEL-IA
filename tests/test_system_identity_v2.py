"""Synthetic and non-invasive Windows process/autorun identity regressions."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from app.config import ScanConfig
from core.evidence_trace import read_evidence_trace
from core.models import ScanStatus, ScanTarget
from core.scanner_manager import ScannerManager
from core.system_identity import (
    direct_autostart_executable, normalize_windows_executable,
    observe_autostart_reference, observe_process_identity,
)
from db.database import SQLiteStore
from engines import process_engine
from engines.persistence_engine import PersistenceEngine


EXE = r"C:\Synthetic\Acme\agent.exe"


class FakeProcess:
    """A fabricated process; no real process is opened in these tests."""

    pid = 42

    def __init__(self, birth: float = 1000.0):
        self.birth = birth

    def create_time(self) -> float:
        return self.birth

    def exe(self) -> str:
        return EXE

    def name(self) -> str:
        return "agent.exe"


def _proc_target(timestamp: float = 1000.0) -> ScanTarget:
    return ScanTarget(
        Path("process_42"), "process", {"pid": 42, "create_time": timestamp},
    )


def _autorun_target(command: str | None = None) -> ScanTarget:
    return ScanTarget(
        Path("persistence_0"), "persistence",
        {"entry": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Synthetic",
         "command": command or f'"{EXE}" --do-not-run',
         "source_type": "registry"},
    )


@pytest.mark.parametrize("command", [
    r'C:\Program Files\Acme\agent.exe --start',
    r'%APPDATA%\agent.exe --start',
    r'C:\Windows\System32\powershell.exe -File C:\Synthetic\safe.ps1',
    r'"C:\Windows\System32\rundll32.exe" C:\Synthetic\module.dll,Start',
    r'cmd.exe /c C:\Synthetic\agent.exe',
    r'\\server\share\agent.exe',
    r'"C:\Synthetic\some.dll" arg',
])
def test_ambiguous_or_interpreted_commands_are_not_linked(command: str) -> None:
    candidate, reason = direct_autostart_executable(command)
    assert candidate == ""
    assert reason


def test_normalize_paths_only_for_absolute_local_windows_paths() -> None:
    assert normalize_windows_executable(r"C:\SYNTHETIC\Acme\agent.EXE") == (
        normalize_windows_executable(EXE)
    )
    assert normalize_windows_executable("agent.exe") == ""
    assert normalize_windows_executable(r"C:\Synthetic\..\Acme\agent.exe") == ""
    assert normalize_windows_executable(r"\\server\share\agent.exe") == ""


def test_verified_pid_and_quoted_autorun_reference_are_separate_observations() -> None:
    process = observe_process_identity(
        _proc_target(), SimpleNamespace(Process=lambda pid: FakeProcess()),
    )
    autorun = observe_autostart_reference(_autorun_target())
    assert process.status == "verified"
    assert process.pid == 42 and process.create_time == 1000.0
    assert process.normalized_executable == autorun.normalized_executable
    assert autorun.status == "reference_only"
    assert len(autorun.command_sha256) == 64
    assert "--do-not-run" not in repr(autorun)


def test_missing_birth_timestamp_and_pid_reuse_are_not_verified() -> None:
    api = SimpleNamespace(Process=lambda pid: FakeProcess(birth=1002.0))
    assert observe_process_identity(_proc_target(), api).status == "stale"
    assert observe_process_identity(
        ScanTarget(Path("process_42"), "process", {"pid": 42}), api,
    ).status == "incomplete"
    assert observe_process_identity(
        _proc_target(), SimpleNamespace(Process=lambda pid: (_ for _ in ()).throw(
            PermissionError("restricted")
        )),
    ).status == "unavailable"


def test_autorun_process_relation_requires_verified_same_session(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """Tests preserve no plaintext command line and invent no attack chain."""
    monkeypatch.setattr(
        process_engine.psutil, "Process", lambda pid: FakeProcess(),
    )
    monkeypatch.setattr(process_engine, "verify_authenticode", lambda path: None)
    store = SQLiteStore(tmp_path / "synthetic.db")
    manager = ScannerManager(
        ScanConfig(database_path=store.path, max_workers=1, max_pending=2),
        store, [process_engine.ProcessEngine(), PersistenceEngine()],
    )
    summary = manager.run([], [_proc_target(), _autorun_target()])
    assert summary.status == ScanStatus.COMPLETED
    assert summary.scanned_system_targets == 2
    assert summary.errors == 0
    observations = store.get_system_observations(summary.session_id)
    assert len(observations) == 2
    assert {row["status"] for row in observations} == {"verified", "reference_only"}
    assert not any("--do-not-run" in repr(row) for row in observations)
    trace = read_evidence_trace(store, summary.session_id)
    links = [item for item in trace.relations if item.kind == "system_link"]
    assert len(links) == 1
    assert "No demuestra que esta entrada iniciara el proceso" in links[0].evidence
    assert "PID 42" in links[0].evidence


def test_stale_pid_and_ambiguous_autorun_exclude_correlation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """Untrustworthy process timestamps cannot be silently marked inspected."""
    monkeypatch.setattr(
        process_engine.psutil, "Process", lambda pid: FakeProcess(birth=1002.0),
    )
    store = SQLiteStore(tmp_path / "stale.db")
    summary = ScannerManager(
        ScanConfig(database_path=store.path, max_workers=1, max_pending=3),
        store, [process_engine.ProcessEngine(), PersistenceEngine()],
    ).run([], [
        _proc_target(),
        _autorun_target(),
    ])
    assert summary.status == ScanStatus.COMPLETED
    assert summary.omitted_checks == 1
    rows = store.get_system_observations(summary.session_id)
    assert any(row["status"] == "stale" for row in rows)
    assert not [
        item for item in read_evidence_trace(store, summary.session_id).relations
        if item.kind == "system_link"
    ]
    assert any(row["state"] == "skipped" for row in store.get_target_engine_runs(
        summary.session_id, Path("process_42")
    ))


def test_identical_paths_in_two_sessions_do_not_correlate(
    tmp_path: Path,
) -> None:
    """A verified process from an old scan cannot link to a new autorun entry."""
    from core.system_identity import SystemObservation

    store = SQLiteStore(tmp_path / "separate.db")
    for session in ("older", "newer"):
        store.start_session(session)
    p = SystemObservation(
        target_path="process_42", kind="process", status="verified",
        executable_path=EXE, normalized_executable=normalize_windows_executable(EXE),
        pid=42, create_time=1000.0,
    )
    a = observe_autostart_reference(_autorun_target())
    store.record_target_engine_runs(
        "older", Path("process_42"), "scanned", [], system_observation=p,
    )
    store.record_target_engine_runs(
        "newer", Path("persistence_0"), "scanned", [], system_observation=a,
    )
    for session in ("older", "newer"):
        assert not any(
            x.kind == "system_link"
            for x in read_evidence_trace(store, session).relations
        )
