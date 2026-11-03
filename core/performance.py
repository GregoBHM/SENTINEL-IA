"""Observed scanner performance and cautious time-to-finish estimates.

All durations use a monotonic clock. Engine durations are additive *CPU/wall*
measurements inside worker threads: concurrent durations are NOT total scan
duration. Input bytes describe target sizes, not actual bytes read from disk.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True, slots=True)
class EngineTiming:
    """A single engine invocation, including intentional skips and failures."""

    engine: str
    status: str
    duration_seconds: float
    input_size_bytes: int
    signal_count: int = 0


class PerformanceMonitor:
    """Collect per-engine metrics without one SQLite write per engine invocation.

    ETA applies only to the *known* queue during discovery. An estimate for the
    complete scan is eligible only after discovery closes. Ranges are deliberately
    broad heuristics, not confidence intervals or guaranteed completion dates.
    """

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        """Initialize counters and a testable monotonic clock."""
        self._clock = clock
        self._lock = threading.Lock()
        self._started = clock()
        self._paused_at: float | None = None
        self._paused_total = 0.0
        self._ended: float | None = None
        self._completed = 0
        self._processed_input_bytes = 0
        self._engine: dict[str, dict[str, int | float]] = {}
        self._samples: deque[tuple[float, int]] = deque(maxlen=120)

    def _active_time(self, now: float) -> float:
        """Calculate active seconds while holding the lock."""
        paused = self._paused_total
        if self._paused_at is not None:
            paused += max(0.0, now - self._paused_at)
        return max(0.0, now - self._started - paused)

    def pause(self) -> None:
        """Stop counting requested idle time, without stopping active workers."""
        with self._lock:
            if self._paused_at is None and self._ended is None:
                self._paused_at = self._clock()

    def resume(self) -> None:
        """Accumulate the time since the previous pause request."""
        with self._lock:
            if self._paused_at is not None:
                self._paused_total += max(0.0, self._clock() - self._paused_at)
                self._paused_at = None

    def record_target(self, *, input_size_bytes: int,
                      timings: list[EngineTiming]) -> None:
        """Record one completed target and aggregate timings by engine."""
        with self._lock:
            self._completed += 1
            self._processed_input_bytes += max(0, input_size_bytes)
            for timing in timings:
                entry = self._engine.setdefault(timing.engine, {
                    "checks": 0, "completed": 0, "skipped": 0, "errors": 0,
                    "duration_seconds": 0.0, "input_size_bytes": 0,
                    "signals": 0,
                })
                entry["checks"] += 1
                if timing.status == "success":
                    entry["completed"] += 1
                elif timing.status == "skipped":
                    entry["skipped"] += 1
                else:
                    entry["errors"] += 1
                entry["duration_seconds"] += max(0.0, timing.duration_seconds)
                entry["input_size_bytes"] += max(0, timing.input_size_bytes)
                entry["signals"] += max(0, timing.signal_count)
            now = self._clock()
            active = self._active_time(now)
            self._samples.append((active, self._completed))
            while len(self._samples) > 2 and active - self._samples[0][0] > 45:
                self._samples.popleft()

    def finish(self) -> None:
        """Freeze elapsed time on completion or failure."""
        with self._lock:
            if self._ended is None:
                self._ended = self._clock()
                if self._paused_at is not None:
                    self._paused_total += max(0.0, self._ended - self._paused_at)
                    self._paused_at = None

    def engine_metrics(self) -> dict[str, dict[str, int | float]]:
        """Return detached engine metrics suitable for local persistence."""
        with self._lock:
            return {name: data.copy() for name, data in self._engine.items()}

    def snapshot(self, *, known_targets: int, discovery_complete: bool,
                 allow_estimate: bool = True) -> dict:
        """Return observed performance and an honest bounded work estimate.

        Estimates require 8 completions and 3 active seconds. A discovered total
        can still grow, so during discovery the estimate is for the *known queue*.
        No estimated time is given after cancellation or while paused.
        """
        with self._lock:
            now = self._ended if self._ended is not None else self._clock()
            elapsed = max(0.0, now - self._started)
            active = self._active_time(now)
            paused = max(0.0, elapsed - active)
            remaining = max(0, known_targets - self._completed)
            throughput = self._completed / active if active > 0 else 0.0
            if (len(self._samples) >= 2
                    and self._samples[-1][0] - self._samples[0][0] >= 3):
                dt = self._samples[-1][0] - self._samples[0][0]
                dcount = self._samples[-1][1] - self._samples[0][1]
                if dt > 0 and dcount > 0:
                    throughput = dcount / dt
            estimate: dict | None = None
            if (allow_estimate and self._paused_at is None
                    and self._ended is None and self._completed >= 8
                    and active >= 3.0 and remaining > 0 and throughput > 0
                    and self._samples and active - self._samples[-1][0] < 15):
                center = remaining / throughput
                estimate = {
                    "scope": "full" if discovery_complete else "known",
                    "seconds": round(center, 1),
                    # These are broad planning bounds, NOT statistical CIs.
                    "low_seconds": round(center * 0.6, 1),
                    "high_seconds": round(center * 1.8, 1),
                    "quality": "orientative",
                }
            return {
                "elapsed_seconds": round(elapsed, 3),
                "active_seconds": round(active, 3),
                "paused_seconds": round(paused, 3),
                "completed_targets": self._completed,
                "known_targets": known_targets,
                "remaining_known": remaining,
                "processed_input_bytes": self._processed_input_bytes,
                "throughput_targets_per_second": round(throughput, 2),
                "discovery_complete": discovery_complete,
                "paused": self._paused_at is not None,
                "eta": estimate,
                "engines": {name: row.copy()
                            for name, row in self._engine.items()},
            }
