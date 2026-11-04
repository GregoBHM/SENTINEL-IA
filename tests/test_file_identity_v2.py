"""Synthetic, read-only regression tests for bounded content identities."""
import hashlib
import os
from pathlib import Path

import pytest

from core.file_identity import observe_file_identity


def test_small_file_digest(tmp_path: Path):
    path = tmp_path / "synthetic.exe"
    data = b"MZ" + b"synthetic harmless fixture" * 100
    path.write_bytes(data)
    result = observe_file_identity(path)
    assert result.status == "observed"
    assert result.sha256 == hashlib.sha256(data).hexdigest()
    assert result.bytes_read == result.file_size == len(data)


def test_limit_does_not_report_partial_hash(tmp_path: Path):
    path = tmp_path / "large.exe"
    path.write_bytes(b"x" * 8193)
    result = observe_file_identity(path, max_bytes=8192, chunk_size=4096)
    assert result.status == "limited"
    assert not result.sha256


def test_exact_size_budget_is_allowed(tmp_path: Path):
    path = tmp_path / "exact.exe"
    path.write_bytes(b"x" * 8192)
    result = observe_file_identity(path, max_bytes=8192, chunk_size=4096)
    assert result.status == "observed"


def test_missing_file_and_directory_are_not_clean(tmp_path: Path):
    assert observe_file_identity(tmp_path / "missing.exe").status == "unavailable"
    assert observe_file_identity(tmp_path).status == "unsupported"


def test_symlink_is_not_followed(tmp_path: Path):
    dest = tmp_path / "target.exe"
    dest.write_bytes(b"harmless")
    link = tmp_path / "link.exe"
    try:
        link.symlink_to(dest)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks unavailable on this host")
    assert observe_file_identity(link).status == "unsupported"


def test_bad_budgets_rejected(tmp_path: Path):
    with pytest.raises(ValueError):
        observe_file_identity(tmp_path, max_bytes=0)
    with pytest.raises(ValueError):
        observe_file_identity(tmp_path, chunk_size=1)


def test_changed_file_is_not_reported_as_observed(tmp_path: Path, monkeypatch):
    path = tmp_path / "changing.exe"
    path.write_bytes(b"a" * 8192)
    original_read = os.read
    mutated = False

    def changing_read(fd, size):
        nonlocal mutated
        data = original_read(fd, size)
        if data and not mutated:
            mutated = True
            with path.open("ab") as file:
                file.write(b"extra")
        return data

    monkeypatch.setattr(os, "read", changing_read)
    result = observe_file_identity(path, chunk_size=4096)
    assert result.status == "changed"
    assert not result.sha256
