"""Synthetic regressions for 3D.4 digest reuse (no malware or network)."""
from __future__ import annotations

import hashlib
from pathlib import Path

from app.config import ScanConfig
from core.file_identity import matches_current_file_identity, observe_file_identity
from core.models import ScanStatus
from core.scanner_manager import ScannerManager
from db.database import SQLiteStore
from engines.hash_engine import HashEngine


def _scan(tmp_path: Path, sample: Path, engine: HashEngine):
    store = engine.store
    return ScannerManager(
        ScanConfig(database_path=store.path, max_workers=1, max_pending=2),
        store, [engine],
    ).run([sample])


def test_verified_pe_uses_single_hash_pass_and_keeps_detection(
    tmp_path: Path, monkeypatch,
):
    sample = tmp_path / "synthetic.exe"
    data = b"MZ" + b"fixture-not-malware" * 60
    sample.write_bytes(data)
    store = SQLiteStore(tmp_path / "db.sqlite")
    digest = hashlib.sha256(data).hexdigest()
    store.add_hash_signature(
        digest, "synthetic-only", "Synthetic test match",
        "Local signature fixture (not malware)",
    )
    engine = HashEngine(store)

    def redundant_read(path):
        raise AssertionError("HashEngine must not read this verified PE twice")

    monkeypatch.setattr(engine, "compute_hashes", redundant_read)
    result = _scan(tmp_path, sample, engine)
    assert result.status == ScanStatus.COMPLETED
    assert result.errors == 0
    assert result.omitted_checks == 0
    assert result.finding_files == 1
    assert result.findings[0].sha256 == digest
    identity = store.get_file_identities(result.session_id)
    assert len(identity) == 1
    assert identity[0]["sha256"] == digest
    assert identity[0]["status"] == "observed"


def test_md5_is_computed_in_same_bounded_read(tmp_path: Path):
    sample = tmp_path / "synthetic.exe"
    content = b"MZ" + b"a" * 4096
    sample.write_bytes(content)
    identity = observe_file_identity(sample)
    assert identity.status == "observed"
    assert identity.sha256 == hashlib.sha256(content).hexdigest()
    assert identity.md5 == hashlib.md5(content, usedforsecurity=False).hexdigest()
    assert matches_current_file_identity(sample, identity)
    sample.write_bytes(content + b"change")
    assert not matches_current_file_identity(sample, identity)


def test_stale_digest_is_invalidated_and_rehashed(
    tmp_path: Path, monkeypatch,
):
    import core.scanner_manager as scanner

    sample = tmp_path / "replace.exe"
    old = b"MZ" + b"old" * 20
    new = b"MZ" + b"new-content" * 45
    sample.write_bytes(old)
    store = SQLiteStore(tmp_path / "db.sqlite")
    engine = HashEngine(store)
    original_observer = scanner.observe_file_identity
    original_hash = engine.compute_hashes
    actual_reads = []

    def observe_and_replace(path):
        identity = original_observer(path)
        assert identity.status == "observed"
        sample.write_bytes(new)
        return identity

    def tracked_hash(path):
        actual_reads.append(path)
        return original_hash(path)

    monkeypatch.setattr(scanner, "observe_file_identity", observe_and_replace)
    monkeypatch.setattr(engine, "compute_hashes", tracked_hash)
    result = _scan(tmp_path, sample, engine)
    assert result.status == ScanStatus.COMPLETED
    assert result.omitted_checks >= 1
    assert len(actual_reads) >= 1
    recorded = store.get_file_identities(result.session_id)
    assert recorded[0]["status"] == "changed"
    assert recorded[0]["sha256"] == ""
    assert result.finding_files == 0
    with store.connection() as connection:
        target = connection.execute(
            "SELECT sha256,status FROM scan_targets WHERE session_id=? AND target_path=?",
            (result.session_id, str(sample.absolute())),
        ).fetchone()
    assert target["sha256"] == hashlib.sha256(new).hexdigest()
    assert target["status"] == "partial"


def test_non_pe_uses_existing_hash_engine_path(tmp_path: Path, monkeypatch):
    sample = tmp_path / "ordinary.txt"
    sample.write_bytes(b"plain text fixture")
    store = SQLiteStore(tmp_path / "db.sqlite")
    engine = HashEngine(store)
    original = engine.compute_hashes
    calls = []

    def count(path):
        calls.append(str(path))
        return original(path)

    monkeypatch.setattr(engine, "compute_hashes", count)
    result = _scan(tmp_path, sample, engine)
    assert result.status == ScanStatus.COMPLETED
    assert result.errors == 0
    assert calls
    assert store.get_file_identities(result.session_id) == []


def test_limited_identity_does_not_skip_regular_hash_engine(
    tmp_path: Path, monkeypatch,
):
    from core.file_identity import FileIdentity
    import core.scanner_manager as scanner

    sample = tmp_path / "large.exe"
    sample.write_bytes(b"MZ" + b"fixture" * 40)
    store = SQLiteStore(tmp_path / "db.sqlite")
    engine = HashEngine(store)
    original = engine.compute_hashes
    calls = []

    monkeypatch.setattr(
        scanner, "observe_file_identity",
        lambda path: FileIdentity(str(path), "limited", reason="Synthetic budget"),
    )

    def fallback(path):
        calls.append(path)
        return original(path)

    monkeypatch.setattr(engine, "compute_hashes", fallback)
    result = _scan(tmp_path, sample, engine)
    assert result.status == ScanStatus.COMPLETED
    assert result.omitted_checks >= 1
    assert calls
    assert store.get_file_identities(result.session_id)[0]["status"] == "limited"
