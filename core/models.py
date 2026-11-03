"""Types shared by the detector, aggregator, persistence and presentation layers."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any


class Severity(StrEnum):
    """Normalized severity levels for detection results."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanStatus(StrEnum):
    """Overall scan lifecycle states."""

    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class ScanTarget:
    """Read-only scan objective, optionally backed by a Windows system record."""

    path: Path
    kind: str = "file"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class FileHashes:
    """Cryptographic fingerprints of a file."""

    sha256: str
    md5: str
    size: int


@dataclass(frozen=True, slots=True)
class Finding:
    """Independent detection by exactly one engine, before correlation."""

    target: str
    engine: str
    threat_type: str
    reason: str
    severity: Severity
    risk_score: int
    confidence: int
    rule_id: str = ""
    evidence_group: str = ""
    sha256: str | None = None
    mitre_techniques: tuple[str, ...] = ()
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Reject invalid scores before a finding reaches storage."""
        if not 0 <= self.risk_score <= 100:
            raise ValueError("risk_score debe estar entre 0 y 100")
        if not 0 <= self.confidence <= 100:
            raise ValueError("confidence debe estar entre 0 y 100")


@dataclass(frozen=True, slots=True)
class AggregatedFinding:
    """User-facing verdict plus the traceable evidence behind it."""

    target: str
    threat_type: str
    severity: Severity
    risk_score: int
    confidence: int
    reason: str
    engines: tuple[str, ...]
    evidence: tuple[Finding, ...]
    sha256: str | None = None
    suppressed: bool = False


@dataclass(frozen=True, slots=True)
class ScanEvent:
    """A transport-neutral event for a future GUI or the Phase 2 CLI."""

    kind: str
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ScanSummary:
    """Final counters and results of a scan."""

    session_id: str
    status: ScanStatus
    discovered_files: int = 0
    scanned_files: int = 0
    scanned_system_targets: int = 0
    finding_files: int = 0
    errors: int = 0
    omitted_checks: int = 0
    findings: list[AggregatedFinding] = field(default_factory=list)
    engine_metrics: dict[str, dict[str, int | float]] = field(default_factory=dict)
