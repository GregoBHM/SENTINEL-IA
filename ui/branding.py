"""Canonical assets shared by the Qt window and the frozen Windows program."""
from __future__ import annotations

from pathlib import Path


def asset_path(filename: str) -> Path:
    """Locate a bundled asset in source mode or PyInstaller one-file mode.

    PyInstaller sets module ``__file__`` inside its temporary extraction folder.
    We deliberately do not write to that folder or depend on the current
    working directory, which can be any location when opening an EXE.
    """
    if Path(filename).name != filename or filename not in {
        "oneguard_logo.png", "SentinelOneGuard.ico"
    }:
        raise ValueError("Asset no permitido")
    return Path(__file__).resolve().parents[1] / "assets" / filename


def logo_path() -> Path:
    """Return the 600px app mark used inside the desktop interface."""
    return asset_path("oneguard_logo.png")


def icon_path() -> Path:
    """Return the multi-size ICO embedded into the Windows executable."""
    return asset_path("SentinelOneGuard.ico")
