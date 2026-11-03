"""Engine inventory semantics: initialized is not equivalent to inspected."""
from __future__ import annotations

from types import SimpleNamespace

from core.engine_inventory import build_engine_inventory


def test_inventory_distinguishes_available_missing_and_not_requested() -> None:
    engines = [
        SimpleNamespace(name="hash"), SimpleNamespace(name="pe_static"),
        SimpleNamespace(name="script_static"), SimpleNamespace(name="archive"),
    ]
    rows = build_engine_inventory(
        engines, inspect_processes=False, inspect_persistence=False,
        online_authorized=True, online_configured=False,
        is_windows=True,
    )
    by_id = {item["id"]: item for item in rows}
    assert by_id["hash"]["state"] == "prepared"
    assert by_id["yara"]["state"] == "unavailable"
    assert by_id["process_network"]["state"] == "not_requested"
    assert by_id["persistence"]["state"] == "not_requested"
    assert by_id["reputation"]["state"] == "unavailable"
    assert "credenciales" in by_id["reputation"]["note"]


def test_requested_process_inventory_requires_observed_targets() -> None:
    engines = [
        SimpleNamespace(name="hash"),
        SimpleNamespace(name="process_network"),
        SimpleNamespace(name="persistence"),
    ]
    by_id = {
        item["id"]: item for item in build_engine_inventory(
            engines, inspect_processes=True, inspect_persistence=True,
            online_authorized=False, online_configured=False,
            is_windows=True, process_targets=25, persistence_targets=0,
        )
    }
    assert by_id["process_network"]["state"] == "prepared"
    assert "25" in by_id["process_network"]["note"]
    assert by_id["persistence"]["state"] == "partial"
    assert by_id["reputation"]["state"] == "not_requested"


def test_windows_inventory_is_never_faked_on_other_os() -> None:
    engine = SimpleNamespace(name="process_network")
    items = build_engine_inventory(
        [engine], inspect_processes=True, inspect_persistence=False,
        online_authorized=False, online_configured=False, is_windows=False,
    )
    by_id = {item["id"]: item for item in items}
    assert by_id["process_network"]["state"] == "unavailable"
    assert by_id["persistence"]["state"] == "not_requested"
