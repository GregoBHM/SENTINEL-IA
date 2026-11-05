"""Bounded, read-only content identity for local executable files.

A digest identifies bytes read in this observation, not the image mapped by a
running process, an Authenticode verdict, or proof that a file is benign.
"""
from __future__ import annotations

import hashlib
import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class FileIdentity:
    path: str
    status: str
    sha256: str = ""
    bytes_read: int = 0
    file_size: int | None = None
    elapsed_seconds: float = 0.0
    reason: str = ""
    # Internal reuse only. MD5 is for legacy cache compatibility, never trust.
    md5: str = ""
    fingerprint: tuple[int, int, int, int, int] | None = None


def _is_windows_reparse_point(value: os.stat_result) -> bool:
    """Avoid hashing through known Windows reparse points, including junctions.

    stat metadata alone cannot defeat hostile concurrent reparse substitutions.
    """
    return bool(getattr(value, "st_file_attributes", 0) & 0x400)


def _fingerprint(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def matches_current_file_identity(path: str | Path, identity: FileIdentity) -> bool:
    """Conservative metadata check for reuse within one scan, not TOCTOU proof."""
    if (identity.status != "observed" or not identity.sha256 or not identity.md5
            or identity.fingerprint is None):
        return False
    try:
        current = os.lstat(path)
        return (stat.S_ISREG(current.st_mode)
                and not stat.S_ISLNK(current.st_mode)
                and not _is_windows_reparse_point(current)
                and _fingerprint(current) == identity.fingerprint)
    except OSError:
        return False


def _same_file(a: os.stat_result, b: os.stat_result) -> bool:
    """Reject changes to identity, size or timestamps while reading."""
    return _fingerprint(a) == _fingerprint(b)


def observe_file_identity(
    path: str | Path,
    *,
    max_bytes: int = 256 * 1024 * 1024,
    max_seconds: float = 5.0,
    chunk_size: int = 1024 * 1024,
) -> FileIdentity:
    """Read regular local file in bounded chunks; never execute or modify it.

    Uses descriptor metadata before and after hashing, plus a fresh path stat.
    This reduces ordinary race errors but is NOT a cryptographic snapshot:
    malicious concurrent writes with restored timestamps and inode replacement
    remain possible. Do not use for an automatic quarantine decision.
    """
    label = str(path)
    started = time.monotonic()
    if max_bytes <= 0 or max_seconds <= 0 or not (4096 <= chunk_size <= 4 * 1024 * 1024):
        raise ValueError("Invalid resource limits")

    def result(status: str, reason: str, *, digest: str = "",
               read: int = 0, size: int | None = None,
               md5_digest: str = "",
               snapshot: tuple[int, int, int, int, int] | None = None) -> FileIdentity:
        return FileIdentity(
            label, status, digest, read, size,
            max(0.0, time.monotonic() - started), reason,
            md5=md5_digest, fingerprint=snapshot,
        )

    try:
        # Refuse path-level symbolic links and other reparse-like cases when
        # detected. A racing replacement is still addressed by fstat/path stat.
        initial = os.lstat(path)
        if stat.S_ISLNK(initial.st_mode) or _is_windows_reparse_point(initial):
            return result("unsupported", "Symlink or reparse point; no content identity")
        if not stat.S_ISREG(initial.st_mode):
            return result("unsupported", "Not a regular file")
        if initial.st_size > max_bytes:
            return result("limited", "File exceeds byte budget", size=initial.st_size)
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags)
        try:
            before = os.fstat(fd)
            if (_is_windows_reparse_point(before) or not stat.S_ISREG(before.st_mode)
                    or not _same_file(initial, before)):
                return result("changed", "File changed between path check and open")
            hasher = hashlib.sha256()
            legacy_md5 = hashlib.md5(usedforsecurity=False)
            count = 0
            while True:
                if time.monotonic() - started >= max_seconds:
                    return result("limited", "Time budget exhausted", read=count, size=before.st_size)
                if count >= max_bytes:
                    # A max-size file may end exactly at the budget.
                    extra = os.read(fd, 1)
                    if extra:
                        return result("limited", "Byte budget exhausted", read=count, size=before.st_size)
                    break
                data = os.read(fd, min(chunk_size, max_bytes - count))
                if not data:
                    break
                count += len(data)
                hasher.update(data)
                legacy_md5.update(data)
            after = os.fstat(fd)
            if (_is_windows_reparse_point(after) or not _same_file(before, after)
                    or count != after.st_size):
                return result("changed", "File metadata or length changed during read",
                              read=count, size=after.st_size)
            # A path could now point to a different file despite an open fd.
            try:
                current = os.lstat(path)
            except OSError:
                return result("changed", "Path disappeared during read", read=count, size=after.st_size)
            if _is_windows_reparse_point(current) or not _same_file(after, current):
                return result("changed", "Path identity changed during read",
                              read=count, size=after.st_size)
            if time.monotonic() - started >= max_seconds:
                return result("limited", "Time budget exhausted", read=count, size=after.st_size)
            return result("observed", "Digest of bytes read; not a malware verdict",
                          digest=hasher.hexdigest(), read=count, size=after.st_size,
                          md5_digest=legacy_md5.hexdigest(), snapshot=_fingerprint(after))
        finally:
            os.close(fd)
    except (OSError, ValueError) as exc:
        return result("unavailable", "Cannot read file: " + type(exc).__name__)
