"""Deterministic performance and conservative ETA regression tests."""
from __future__ import annotations

from core.performance import EngineTiming, PerformanceMonitor


class FakeClock:
    """Controllable monotonic source without sleeps."""

    def __init__(self) -> None:
        """Initialize synthetic monotonic seconds."""
        self.now = 100.0

    def __call__(self) -> float:
        """Return the current synthetic time."""
        return self.now


def test_eta_is_known_queue_only_until_discovery_finishes() -> None:
    """Never present dynamic discovered totals as scan-wide completion ETA."""
    clock = FakeClock()
    monitor = PerformanceMonitor(clock)
    for _ in range(10):
        clock.now += 1
        monitor.record_target(
            input_size_bytes=512,
            timings=[EngineTiming("hash", "success", 0.05, 512)],
        )
    partial = monitor.snapshot(known_targets=20, discovery_complete=False)
    assert partial["completed_targets"] == 10
    assert partial["remaining_known"] == 10
    assert partial["eta"]["scope"] == "known"
    assert partial["eta"]["low_seconds"] < partial["eta"]["seconds"]
    assert partial["eta"]["high_seconds"] > partial["eta"]["seconds"]
    assert partial["processed_input_bytes"] == 5120
    complete_scope = monitor.snapshot(
        known_targets=20, discovery_complete=True
    )
    assert complete_scope["eta"]["scope"] == "full"
    assert complete_scope["eta"]["quality"] == "orientative"


def test_insufficient_samples_pause_cancel_and_finish_never_invent_eta() -> None:
    """No ETA for tiny scans, while paused, after cancellation or completion."""
    clock = FakeClock()
    monitor = PerformanceMonitor(clock)
    for _ in range(5):
        clock.now += 1
        monitor.record_target(input_size_bytes=8, timings=[])
    assert monitor.snapshot(known_targets=20, discovery_complete=False)["eta"] is None
    for _ in range(5):
        clock.now += 1
        monitor.record_target(input_size_bytes=8, timings=[])
    assert monitor.snapshot(known_targets=20, discovery_complete=True)["eta"]
    monitor.pause()
    clock.now += 30
    assert monitor.snapshot(known_targets=20, discovery_complete=True)["eta"] is None
    monitor.resume()
    observed = monitor.snapshot(known_targets=20, discovery_complete=True)
    assert observed["paused_seconds"] == 30
    assert monitor.snapshot(
        known_targets=20, discovery_complete=True, allow_estimate=False
    )["eta"] is None
    monitor.finish()
    clock.now += 90
    frozen = monitor.snapshot(known_targets=20, discovery_complete=True)
    assert frozen["eta"] is None
    assert frozen["elapsed_seconds"] == 40


def test_engine_metrics_differentiate_success_skip_and_error() -> None:
    """Input bytes and sum of worker durations are not disk bandwidth."""
    clock = FakeClock()
    monitor = PerformanceMonitor(clock)
    monitor.record_target(input_size_bytes=17, timings=[
        EngineTiming("yara", "success", 0.02, 17),
        EngineTiming("pe", "skipped", 0.01, 17),
    ])
    monitor.record_target(input_size_bytes=21, timings=[
        EngineTiming("yara", "error", 0.03, 21),
        EngineTiming("pe", "success", 0.04, 21),
    ])
    metrics = monitor.engine_metrics()
    assert metrics["yara"]["checks"] == 2
    assert metrics["yara"]["completed"] == 1
    assert metrics["yara"]["errors"] == 1
    assert metrics["pe"]["skipped"] == 1
    assert metrics["pe"]["input_size_bytes"] == 38
    assert round(metrics["pe"]["duration_seconds"], 3) == 0.05
    metrics["pe"]["checks"] = -1
    assert monitor.engine_metrics()["pe"]["checks"] == 2
