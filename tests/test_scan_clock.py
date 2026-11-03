"""Unit tests for observable scan timing (no Qt or Windows needed)."""
from __future__ import annotations

from core.scan_clock import ScanClock, format_duration


class FakeClock:
    """Deterministic monotonic time source for scan timing tests."""

    def __init__(self) -> None:
        """Initialize an unambiguous time origin."""
        self.now = 100.0

    def __call__(self) -> float:
        """Return monotonic time in seconds."""
        return self.now


def test_elapsed_and_observed_throughput() -> None:
    """Duration and rate derive only from completed targets and elapsed time."""
    clock = FakeClock()
    scan = ScanClock(clock)
    clock.now += 10
    scan.set_processed(50)
    result = scan.snapshot()
    assert result.elapsed_seconds == 10
    assert result.active_seconds == 10
    assert result.files_per_second == 5
    assert not result.paused


def test_pause_excludes_idle_duration() -> None:
    """Pauses are tracked separately and do not restart the clock."""
    clock = FakeClock()
    scan = ScanClock(clock)
    clock.now += 2
    scan.pause()
    scan.pause()
    clock.now += 8
    assert scan.snapshot().paused
    scan.resume()
    clock.now += 5
    scan.set_processed(14)
    result = scan.snapshot()
    assert result.elapsed_seconds == 15
    assert result.paused_seconds == 8
    assert result.active_seconds == 7
    assert result.files_per_second == 2


def test_finish_freezes_counters() -> None:
    """The UI must not keep increasing elapsed time after a failed scan."""
    clock = FakeClock()
    scan = ScanClock(clock)
    clock.now += 3
    scan.finish()
    clock.now += 100
    assert scan.snapshot().elapsed_seconds == 3


def test_format_duration_never_invents_eta() -> None:
    """Format observed timing in minutes or hours only."""
    assert format_duration(7) == "00:07"
    assert format_duration(65) == "01:05"
    assert format_duration(3723) == "1:02:03"
    assert format_duration(-2) == "00:00"
