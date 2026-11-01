"""Persistence and atomic quota tests."""
import hashlib

import pytest

from db.database import SQLiteStore


def test_signature_roundtrip(store: SQLiteStore) -> None:
    """Store reviewed metadata and retrieve by digest."""
    sha = hashlib.sha256(b"safe synthetic payload").hexdigest()
    store.add_hash_signature(sha, "synthetic", "Test", "Only a unit test", 55, 75)
    assert store.get_hash_signature(sha)["risk_score"] == 55
    assert store.get_hash_signature("f" * 64) is None


def test_invalid_signature_rejected(store: SQLiteStore) -> None:
    """Invalid digests must never enter the local signature DB."""
    with pytest.raises(ValueError):
        store.add_hash_signature("abc", "bad", "Test", "Invalid")


def test_daily_quota_is_bounded(store: SQLiteStore) -> None:
    """Persistent quotas cannot be incremented past the configured cap."""
    assert store.reserve_daily_request("test-vendor", 2)
    assert store.reserve_daily_request("test-vendor", 2)
    assert not store.reserve_daily_request("test-vendor", 2)
