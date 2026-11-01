"""Fake Windows registry/process APIs: absolutely no OS changes during tests."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.models import AggregatedFinding, Finding, Severity
from core.remediation_policy import RemediationDenied
from core import persistence_response, process_response


class FakeKey:
    """Simple context-manager proxy for a fake HKCU registry handle."""

    def __init__(self, backend):
        self.backend = backend

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class FakeWinreg:
    """Local dictionary emulating supported winreg calls without touching Windows."""

    HKEY_CURRENT_USER = 1
    KEY_QUERY_VALUE = 2
    KEY_SET_VALUE = 4
    REG_SZ = 1
    REG_EXPAND_SZ = 2

    def __init__(self, original):
        self.values = {"OneGuardSyntheticTest": (original, self.REG_SZ)}

    def OpenKey(self, hive, path, zero, flags):  # noqa: N802
        """Accept only the HKCU key under test."""
        assert hive == self.HKEY_CURRENT_USER
        assert path in persistence_response._ALLOWED
        return FakeKey(self)

    def QueryValueEx(self, key, name):  # noqa: N802
        """Return an existing value or raise a genuine-style not-found error."""
        if name not in self.values:
            raise FileNotFoundError(name)
        return self.values[name]

    def DeleteValue(self, key, name):  # noqa: N802
        """Delete only from an in-memory dictionary."""
        del self.values[name]

    def SetValueEx(self, key, name, reserved, type_, value):  # noqa: N802
        """Restore the in-memory value without running the command."""
        self.values[name] = (value, type_)


def _autorun_finding(store, command: str, entry: str):
    """Insert a suspicious synthetic persistence evidence record."""
    signal = Finding(target=entry, engine="persistence", threat_type="Persistencia sospechosa",
                     reason="Ejemplo sintético", severity=Severity.MEDIUM,
                     risk_score=50, confidence=55,
                     details={"source_entry": entry, "source_type": "registry",
                              "command_sha256": hashlib.sha256(command[:4096].encode()).hexdigest()})
    verdict = AggregatedFinding(entry, "Persistencia sospechosa", Severity.MEDIUM,
                                50, 55, signal.reason, ("persistence",), (signal,))
    store.save_finding("test-session", verdict)
    with store.connection() as conn:
        return conn.execute("SELECT id FROM findings ORDER BY id DESC LIMIT 1").fetchone()[0]


def test_hkcu_autorun_can_be_disabled_and_restored_with_mock_api(sample, monkeypatch):
    """Check backup, identity matching, confirmation and reversible mutation."""
    store, *_ = sample
    command = r'C:\Users\Demo\AppData\Roaming\synthetic.exe'
    key = r"Software\Microsoft\Windows\CurrentVersion\Run"
    finding_id = _autorun_finding(store, command, f"HKCU\\{key}\\OneGuardSyntheticTest")
    fake = FakeWinreg(command)
    monkeypatch.setattr(persistence_response, "winreg", fake)
    monkeypatch.setattr(persistence_response, "os", SimpleNamespace(name="nt"))
    handler = persistence_response.PersistenceResponse(store)
    operation_id = handler.disable_hkcu_run(finding_id, confirmation="DESACTIVAR INICIO")
    assert fake.values == {}
    with store.connection() as conn:
        row = conn.execute("SELECT status,value_data FROM disabled_autoruns").fetchone()
        assert row["status"] == "disabled" and row["value_data"] == command
    handler.restore_hkcu_run(operation_id, confirmation="RESTAURAR INICIO")
    assert fake.values["OneGuardSyntheticTest"] == (command, fake.REG_SZ)


def test_hkcu_autorun_rejects_stale_registry_value(sample, monkeypatch):
    """A changed command line cannot be removed without another scan."""
    store, *_ = sample
    original = r'C:\Users\Demo\AppData\Roaming\safe.exe'
    key = r"Software\Microsoft\Windows\CurrentVersion\Run"
    fid = _autorun_finding(store, original, f"HKCU\\{key}\\OneGuardSyntheticTest")
    fake = FakeWinreg(r'C:\Users\Demo\AppData\Roaming\changed.exe')
    monkeypatch.setattr(persistence_response, "winreg", fake)
    monkeypatch.setattr(persistence_response, "os", SimpleNamespace(name="nt"))
    with pytest.raises(RemediationDenied, match="cambió"):
        persistence_response.PersistenceResponse(store).disable_hkcu_run(fid, confirmation="DESACTIVAR INICIO")
    assert fake.values


def test_registry_rejects_hklm_even_with_matching_content(sample, monkeypatch):
    """High-integrity machine-wide autoruns are never changed."""
    store, *_ = sample
    command = r'C:\Users\Demo\AppData\Roaming\synthetic.exe'
    key = r"Software\Microsoft\Windows\CurrentVersion\Run"
    fid = _autorun_finding(store, command, f"HKLM\\{key}\\OneGuardSyntheticTest")
    fake = FakeWinreg(command)
    monkeypatch.setattr(persistence_response, "winreg", fake)
    monkeypatch.setattr(persistence_response, "os", SimpleNamespace(name="nt"))
    with pytest.raises(RemediationDenied, match="HKCU"):
        persistence_response.PersistenceResponse(store).disable_hkcu_run(fid, confirmation="DESACTIVAR INICIO")
    assert fake.values


def test_process_critical_name_is_not_terminated(sample, monkeypatch):
    """A fake critical Windows process is denied before any termination call."""
    store, file, *_ = sample
    class FakeProcess:
        """Synthetic process identity and termination counter."""
        terminated = False

        def create_time(self):
            return 123.0

        def name(self):
            return "lsass.exe"

        def exe(self):
            return str(file)

        def terminate(self):
            self.terminated = True

    fake = FakeProcess()
    class FakeNoSuchProcess(Exception):
        """Synthetic psutil process error."""
    class FakeAccessDenied(Exception):
        """Synthetic psutil access error."""
    fake_psutil = SimpleNamespace(Process=lambda pid: fake, NoSuchProcess=FakeNoSuchProcess,
                                  AccessDenied=FakeAccessDenied, TimeoutExpired=TimeoutError)
    monkeypatch.setattr(process_response, "psutil", fake_psutil)
    monkeypatch.setattr(process_response, "os", SimpleNamespace(name="nt", getpid=lambda: 9999))
    with pytest.raises(RemediationDenied, match="protegido"):
        process_response.ProcessResponse(store).terminate(4321, 123.0, str(file),
                                                        confirmation="FINALIZAR PROCESO")
    assert not fake.terminated
