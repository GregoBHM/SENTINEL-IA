"""Monotonic scan timing without invented completion estimates.

This module is GUI-independent and never reads or modifies scanned targets.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True, slots=True)
class ScanTiming:
    """Observed scan duration, effective work time and throughput."""

    elapsed_seconds: float
    active_seconds: float
    paused_seconds: float
    processed: int
    files_per_second: float
    paused: bool


class ScanClock:
    """Measure actual scan activity, excluding user-initiated pause from rate."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        """Start a new monotonic measurement using an injectable clock."""
        self._clock = clock
        self.reset()

    def reset(self) -> None:
        """Start a fresh scan, clearing counters and previous pause durations."""
        self._started = self._clock()
        self._paused_at: float | None = None
        self._paused_total = 0.0
        self._ended_at: float | None = None
        self._processed = 0

    def set_processed(self, count: int) -> None:
        """Record the actual number of completed targets, never an estimate."""
        self._processed = max(0, int(count))

    def pause(self) -> None:
        """Mark a requested pause exactly once."""
        if self._ended_at is None and self._paused_at is None:
            self._paused_at = self._clock()

    def resume(self) -> None:
        """Resume the active scan and account for time spent paused."""
        if self._paused_at is not None:
            self._paused_total += max(0.0, self._clock() - self._paused_at)
            self._paused_at = None

    def finish(self) -> None:
        """Freeze measurement after completion, cancellation or failure."""
        if self._ended_at is None:
            self._ended_at = self._clock()
            if self._paused_at is not None:
                self._paused_total += max(0.0, self._ended_at - self._paused_at)
                self._paused_at = None

    def snapshot(self) -> ScanTiming:
        """Report observed data; never extrapolate an unreliable ETA."""
        now = self._ended_at if self._ended_at is not None else self._clock()
        elapsed = max(0.0, now - self._started)
        paused = self._paused_total
        if self._paused_at is not None:
            paused += max(0.0, now - self._paused_at)
        active = max(0.0, elapsed - paused)
        return ScanTiming(
            elapsed_seconds=elapsed,
            active_seconds=active,
            paused_seconds=paused,
            processed=self._processed,
            files_per_second=self._processed / active if active > 0 else 0.0,
            paused=self._paused_at is not None,
        )


def format_duration(seconds: float) -> str:
    """Format observed duration for compact UI and history labels."""
    total = max(0, int(seconds))
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{hours:d}:{minutes:02d}:{secs:02d}" if hours else f"{minutes:02d}:{secs:02d}"
