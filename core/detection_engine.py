"""Contract followed by all detection engines."""
from abc import ABC, abstractmethod

from core.models import Finding, ScanTarget


class DetectionEngine(ABC):
    """Analyze a single target without changing its contents or permissions."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the stable engine identifier."""

    @abstractmethod
    def scan(self, target: ScanTarget) -> list[Finding]:
        """Return evidence; never delete or quarantine anything."""
