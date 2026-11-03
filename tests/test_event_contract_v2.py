"""Contract tests for translated, structured v2 events."""
from __future__ import annotations

from core.events import make_event, present_event
from core.models import ScanEvent


def test_reputation_notice_is_not_malware_or_coverage() -> None:
    """Missing API credentials are informational and do not alter local detection."""
    event = make_event(
        "warning", "SCAN.REPUTATION.UNCONFIGURED", engine="reputation"
    )
    message = present_event(event)
    assert event.payload["schema_version"] == 1
    assert event.payload["event_id"]
    assert event.payload["timestamp_utc"].endswith("+00:00")
    assert message.category == "information"
    assert message.level == "INFO"
    assert "locales" in message.description


def test_yara_size_limitation_preserves_machine_readable_bytes() -> None:
    """YARA coverage omissions remain distinct from confirmed infections."""
    event = make_event(
        "skipped", "SCAN.YARA.SIZE_LIMIT", engine="yara",
        path="example.exe",
        params={"size_bytes": 100 * 1024**2, "limit_bytes": 64 * 1024**2},
    )
    msg = present_event(event)
    assert msg.category == "coverage"
    assert msg.level == "WARN"
    assert "64 MiB" in msg.description
    assert "100.0 MiB" in msg.description
    assert event.payload["message_params"]["size_bytes"] == 104857600
    assert msg.dedupe_key == "SCAN.YARA.SIZE_LIMIT:yara"


def test_legacy_events_remain_readable() -> None:
    """Older raw event producers must not break the dashboard."""
    old = ScanEvent("skipped", {"message": "legacy reason", "path": "x"})
    assert present_event(old).code == "SCAN.ENGINE.SKIPPED"
    old_notice = ScanEvent(
        "warning", {"message": "Reputación externa autorizada, pero no hay API keys"}
    )
    assert present_event(old_notice).category == "information"


def test_unknown_event_codes_are_rejected() -> None:
    """The public event vocabulary cannot silently drift."""
    import pytest

    with pytest.raises(ValueError):
        make_event("skipped", "UNKNOWN.RULE")
