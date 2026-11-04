"""Contract followed by all detection engines."""
from abc import ABC, abstractmethod

from core.models import Finding, ScanTarget


class DetectionEngine(ABC):
    """Analyze a single target without changing its contents or permissions."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the stable engine identifier."""

    def applies_to(self, target: ScanTarget, file_header: bytes | None = None) -> bool:
        """Return eligibility, not a verdict. Third-party engines default to applicable.

        Built-in engines override this predicate to avoid reporting irrelevant
        targets as successfully inspected. No target is executed or modified.
        """
        return True

    @abstractmethod
    def scan(self, target: ScanTarget) -> list[Finding]:
        """Return evidence; never delete or quarantine anything."""
