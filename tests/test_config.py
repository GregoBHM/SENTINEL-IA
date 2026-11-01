"""Configuration and consent semantics."""
from pathlib import Path

import pytest

from app.config import load_config_file


def test_toml_loads_resource_limits(tmp_path: Path) -> None:
    """User-defined limits should not require Python source edits."""
    path = tmp_path / "config.toml"
    path.write_text("[scanner]\nmax_workers=2\nmax_pending=8\n", encoding="utf-8")
    config = load_config_file(path)
    assert config.max_workers == 2
    assert config.max_pending == 8
    assert config.online_enabled is False


def test_toml_cannot_include_api_keys(tmp_path: Path) -> None:
    """Reject plain-text API keys in the configuration file."""
    path = tmp_path / "config.toml"
    path.write_text('[reputation]\napi_key="do-not-store"\n', encoding="utf-8")
    with pytest.raises(ValueError):
        load_config_file(path)
