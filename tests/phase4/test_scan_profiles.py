"""Phase 4 wizard consent and scope tests independent of Qt."""
from pathlib import Path

import pytest

from ui.profiles import ScanSelection, build_plan, default_quick_roots


def selection(tmp_path: Path, **overrides) -> ScanSelection:
    """Create synthetic permissions and a safe custom target."""
    base = dict(profile="custom", read_files=True, inspect_processes=False,
                inspect_persistence=False, online_hashes=False,
                custom_paths=(tmp_path,))
    return ScanSelection(**(base | overrides))


def test_deny_files_prevents_start(tmp_path: Path) -> None:
    """No file read is possible without explicit consent."""
    with pytest.raises(ValueError, match="autorizar"):
        build_plan(selection(tmp_path, read_files=False))


def test_custom_requires_selected_path(tmp_path: Path) -> None:
    """Do not interpret an empty custom selection as full disk scan."""
    with pytest.raises(ValueError, match="Selecciona"):
        build_plan(selection(tmp_path, custom_paths=()))


def test_nonexistent_selected_target_is_not_scanned(tmp_path: Path) -> None:
    """Nonexistent custom paths are rejected before any file reads."""
    with pytest.raises(ValueError):
        build_plan(selection(tmp_path, custom_paths=(tmp_path / "unknown",)))


def test_custom_deduplicates_paths(tmp_path: Path) -> None:
    """Duplicate paths must not silently expand scope."""
    plan = build_plan(selection(tmp_path, custom_paths=(tmp_path, tmp_path)))
    assert plan.roots == (tmp_path,)
    assert not plan.online


def test_online_is_opt_in(tmp_path: Path) -> None:
    """Hash API access remains disabled unless the checkbox is checked."""
    assert build_plan(selection(tmp_path)).online is False
    assert build_plan(selection(tmp_path, online_hashes=True)).online is True


def test_system_permissions_are_independent(tmp_path: Path) -> None:
    """Process inventory does not imply registry consent."""
    plan = build_plan(selection(tmp_path, inspect_processes=True))
    assert plan.processes
    assert not plan.persistence


def test_no_quick_roots_does_not_trigger_disk_scan(tmp_path: Path) -> None:
    """Fail closed rather than broaden scanning unexpectedly."""
    request = selection(tmp_path, profile="quick")
    with pytest.raises(ValueError):
        build_plan(request, quick_roots=lambda: ())


def test_quick_roots_use_only_existing_folders(tmp_path: Path) -> None:
    """A generated sandbox user's folders are the only quick candidates."""
    (tmp_path / "Downloads").mkdir()
    result = default_quick_roots({"USERPROFILE": str(tmp_path)})
    assert result == (tmp_path / "Downloads",)
