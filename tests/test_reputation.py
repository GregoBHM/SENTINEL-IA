"""HTTP reputation tests use mock responses, never contact providers."""
from pathlib import Path
from typing import Any

import pytest

from app.config import ScanConfig
from core.reputation_client import ReputationClient, SlidingWindowLimiter
from db.database import SQLiteStore


class FakeResponse:
    """A minimal requests.Response double."""

    status_code = 200

    def raise_for_status(self) -> None:
        """Simulate success."""
        return None

    def json(self) -> dict[str, Any]:
        """Return a synthetic positive match without actual malware metadata."""
        return {"query_status": "ok", "data": [{"signature": "SyntheticFamily"}]}


class FakeSession:
    """Track any attempted HTTP calls without network access."""

    def __init__(self) -> None:
        """Reset the request counter."""
        self.calls = []

    def post(
        self, url: str, *, data: dict[str, str],
        headers: dict[str, str], timeout: Any,
    ) -> FakeResponse:
        """Record a hash-only query and return synthetic data."""
        self.calls.append((url, data, headers))
        return FakeResponse()


def test_offline_mode_makes_no_requests(store: SQLiteStore) -> None:
    """No consent means zero network calls, even if an API key is configured."""
    config = ScanConfig(online_consent=False, online_enabled=False, mb_api_key="test-key")
    session = FakeSession()
    client = ReputationClient(config, store, session=session)  # type: ignore[arg-type]
    assert client.check("a" * 64) == []
    assert not session.calls


def test_online_queries_hash_only_and_caches(store: SQLiteStore) -> None:
    """Only SHA-256 leaves the host, and repeated lookups use SQLite."""
    config = ScanConfig(online_consent=True, online_enabled=True,
                        mb_api_key="test-key", vt_api_key="")
    session = FakeSession()
    client = ReputationClient(config, store, session=session)  # type: ignore[arg-type]
    assert client.check("a" * 64)[0].status == "malicious"
    assert session.calls[0][1] == {"query": "get_info", "hash": "a" * 64}
    assert client.check("a" * 64)[0].status == "malicious"
    assert len(session.calls) == 1


def test_online_requires_explicit_consent() -> None:
    """Reject a configuration that enables network activity without consent."""
    with pytest.raises(ValueError):
        ScanConfig(online_enabled=True, online_consent=False)


def test_window_rate_limiter() -> None:
    """Rate control must not block a scanning worker."""
    limiter = SlidingWindowLimiter(2)
    assert limiter.allow()
    assert limiter.allow()
    assert not limiter.allow()
