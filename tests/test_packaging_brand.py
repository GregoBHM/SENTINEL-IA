"""Static packaging regressions runnable without Windows or PyInstaller."""
from __future__ import annotations

from pathlib import Path
from PIL import Image
import pytest

from app.config import ScanConfig
from ui.branding import asset_path, icon_path, logo_path

ROOT = Path(__file__).resolve().parents[1]


def test_assets_resolve_relative_to_project_not_cwd(monkeypatch, tmp_path: Path) -> None:
    """Running from arbitrary working directory still finds the real icon."""
    monkeypatch.chdir(tmp_path)
    assert logo_path().is_file()
    assert icon_path().is_file()


def test_windows_icon_contains_explorer_sizes() -> None:
    """The ICO carries embedded 16px, 32px, 48px and 256px frames."""
    with Image.open(icon_path()) as ico:
        sizes = ico.info.get('sizes', set())
        for expected in ((16, 16), (32, 32), (48, 48), (256, 256)):
            assert expected in sizes


def test_brand_logo_has_alpha_and_sufficient_resolution() -> None:
    """Keep the source image crisp for UI rendering."""
    with Image.open(logo_path()) as logo:
        assert logo.size[0] >= 512
        assert logo.mode == 'RGBA'


def test_disallow_path_traversal() -> None:
    """Only approved bundled UI files may be resolved."""
    with pytest.raises(ValueError):
        asset_path('../../private.txt')


def test_packager_includes_assets_and_rules() -> None:
    """The declared packaging must include the detectors' rule folder."""
    spec = (ROOT / 'build.spec').read_text(encoding='utf-8')
    assert "'assets'" in spec
    assert "'rules/bundled'" in spec
    assert "(str(root / 'db' / 'schema.sql'), 'db')" in spec
    assert 'uac_admin=' in spec
    assert 'console=False' in spec
    assert "SentinelOneGuard.ico" in spec
    assert ScanConfig().rule_directory.is_dir()
