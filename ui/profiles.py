"""Consent and scan-scope planning without depending on the Qt runtime.

Every location is user-selected or derived from well-known OS folders. The
planner does not read content, inspect processes, or invoke any network APIs.
"""
from __future__ import annotations

import ctypes
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


@dataclass(frozen=True, slots=True)
class ScanSelection:
    """Scope and explicit permissions supplied by the wizard."""

    profile: str
    read_files: bool
    inspect_processes: bool
    inspect_persistence: bool
    online_hashes: bool
    custom_paths: tuple[Path, ...] = ()


@dataclass(frozen=True, slots=True)
class ScanPlan:
    """Validated, read-only scan plan for a coordinator."""

    roots: tuple[Path, ...]
    processes: bool
    persistence: bool
    online: bool
    profile: str


def default_quick_roots(environ: dict[str, str] | None = None) -> tuple[Path, ...]:
    """Choose existing high-interest folders without traversing the entire disk."""
    env = os.environ if environ is None else environ
    home = Path(env.get("USERPROFILE") or Path.home())
    candidates: list[Path] = [
        home / "Downloads", home / "Desktop", home / "Documents",
    ]
    for name, tail in (
        ("TEMP", ""), ("APPDATA", ""), ("LOCALAPPDATA", "Temp"),
        ("PROGRAMDATA", ""),
    ):
        if env.get(name):
            candidates.append(Path(env[name]) / tail)
    return _existing_unique(candidates)


def fixed_drives() -> tuple[Path, ...]:
    """Return only local fixed Windows disks; no silent network-drive scanning."""
    if sys.platform != "win32":
        return ()
    kernel = ctypes.windll.kernel32
    bitmask = int(kernel.GetLogicalDrives())
    results = []
    for index in range(26):
        if not bitmask & (1 << index):
            continue
        root = f"{chr(ord('A') + index)}:\\"
        if kernel.GetDriveTypeW(root) == 3:  # DRIVE_FIXED
            results.append(Path(root))
    return tuple(results)


def _existing_unique(paths: list[Path] | tuple[Path, ...]) -> tuple[Path, ...]:
    """Filter nonexistent locations, duplicates and Windows symlink shortcuts."""
    output: list[Path] = []
    seen: set[str] = set()
    for candidate in paths:
        path = Path(candidate).expanduser().absolute()
        key = os.path.normcase(str(path))
        if key not in seen and path.exists() and not path.is_symlink():
            output.append(path)
            seen.add(key)
    return tuple(output)


def build_plan(
    selection: ScanSelection,
    *, quick_roots: Callable[[], tuple[Path, ...]] = default_quick_roots,
    disk_roots: Callable[[], tuple[Path, ...]] = fixed_drives,
) -> ScanPlan:
    """Validate wizard choices before reading any file or system object."""
    if not selection.read_files:
        raise ValueError("Debes autorizar la lectura de archivos para iniciar.")
    if selection.profile not in {"quick", "full", "custom"}:
        raise ValueError("Selecciona un tipo de análisis válido.")
    if selection.profile == "quick":
        roots = quick_roots()
    elif selection.profile == "full":
        roots = disk_roots()
    else:
        roots = _existing_unique(selection.custom_paths)
    if selection.profile == "custom" and not roots:
        raise ValueError("Selecciona al menos un archivo o carpeta existente.")
    if not roots and not (selection.inspect_processes or selection.inspect_persistence):
        raise ValueError("No hay rutas accesibles para analizar.")
    return ScanPlan(
        roots=roots,
        processes=selection.inspect_processes,
        persistence=selection.inspect_persistence,
        online=selection.online_hashes,
        profile=selection.profile,
    )
