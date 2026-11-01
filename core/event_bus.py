"""Thread-safe queue for scan events. UI consumes without cross-thread widget calls."""
from __future__ import annotations

from queue import Empty, Full, Queue

from core.models import ScanEvent


class EventBus:
    """Bounded in-memory transport that never blocks a scanner indefinitely."""

    def __init__(self, maxsize: int = 5000) -> None:
        """Create a bounded event queue."""
        self.queue: Queue[ScanEvent] = Queue(maxsize=maxsize)
        self.dropped_progress = 0

    def publish(self, event: ScanEvent) -> None:
        """Publish a scan event; non-critical progress may be dropped if full."""
        try:
            self.queue.put_nowait(event)
        except Full:
            # Prefer critical events over older buffered events when the queue is saturated.
            if event.kind in {"error", "complete", "finding"}:
                try:
                    self.queue.get_nowait()
                    self.queue.put_nowait(event)
                except (Empty, Full):
                    pass
            else:
                self.dropped_progress += 1

    def get_nowait(self) -> ScanEvent:
        """Return the oldest pending event or raise queue.Empty."""
        return self.queue.get_nowait()
