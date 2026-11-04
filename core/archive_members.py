"""Immutable local-only coverage evidence for archive members."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ArchiveMemberCoverage:
    """A member's observed processing status, never a malware verdict.

    Inspected means the supported in-memory inspection pipeline was invoked;
    it does not certify all nested content or detection of every threat.
    """

    member_path: str
    archive_format: str
    status: str
    reason: str = ""
    bytes_read: int = 0
    depth: int = 1
    checks: tuple[str, ...] = ()
