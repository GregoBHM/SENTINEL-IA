"""Bounded magic-prefix routing for supported archive formats.

Magic takes precedence over extensions, including archives renamed to .dat.
A known archive extension remains a fallback when bytes are inaccessible or
invalid so that a corrupt container produces an explicit coverage limitation.
This is a format hint, not a security verdict or a full parser.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class ArchiveIdentity:
    """A supported container format and how it was recognized."""

    kind: str
    source: str


_BY_EXTENSION = {".zip": "zip", ".rar": "rar", ".7z": "7z"}


def identify_archive(prefix: bytes | None, filename: str | Path) -> ArchiveIdentity | None:
    """Identify ZIP, RAR4/RAR5 or 7z without decompressing or opening the file."""
    if prefix:
        if prefix.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
            return ArchiveIdentity("zip", "magic")
        if prefix.startswith((b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00")):
            return ArchiveIdentity("rar", "magic")
        if prefix.startswith(b"7z\xbc\xaf\x27\x1c"):
            return ArchiveIdentity("7z", "magic")
    kind = _BY_EXTENSION.get(Path(filename).suffix.lower())
    return ArchiveIdentity(kind, "extension") if kind else None
