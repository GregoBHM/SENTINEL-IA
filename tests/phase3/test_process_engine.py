"""Process simulations never query sensitive actual live process data."""
from pathlib import Path
from types import SimpleNamespace

from core.models import ScanTarget
from engines import process_engine as module


class FakeProc:
    """Fake psutil Process holding only synthetic metadata."""
    pid = 42

    def create_time(self) -> float:
        """Return stable synthetic process birth time."""
        return 1000.0

    def name(self) -> str:
        """Return common Windows masquerade spelling."""
        return "svch0st.exe"

    def exe(self) -> str:
        """Return fabricated path in writable profile."""
        return r"C:\Users\test\AppData\Roaming\svch0st.exe"

    def net_connections(self, kind: str) -> list[object]:
        """Provide simulated network metadata without actual destinations."""
        return [SimpleNamespace(raddr=("example.invalid", 443), status="ESTABLISHED")]


def test_synthetic_process_spoof(monkeypatch) -> None:
    """Report name + writable path, without attributing credential theft."""
    monkeypatch.setattr(module.psutil, "Process", lambda pid: FakeProc())
    target = ScanTarget(Path("process_42"), "process", {"pid": 42, "create_time": 1000})
    finding = module.ProcessEngine().scan(target)[0]
    assert finding.risk_score < 80
    assert finding.details["established_remote_connections"] == 1
    assert "exfiltración" in finding.details["network_inspection"]


def test_pid_reuse_is_not_analyzed(monkeypatch) -> None:
    """Skip recycled process IDs instead of applying a stale identity."""
    monkeypatch.setattr(module.psutil, "Process", lambda pid: FakeProc())
    target = ScanTarget(Path("process_42"), "process", {"pid": 42, "create_time": 999})
    assert module.ProcessEngine().scan(target) == []
