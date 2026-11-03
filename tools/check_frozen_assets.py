"""Verify required data really lives inside a PyInstaller one-file executable.

This static inspection does not execute the unsigned elevated program.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from PyInstaller.archive.readers import CArchiveReader


REQUIRED = frozenset({
    "db/schema.sql",
    "assets/oneguard_logo.png",
    "assets/SentinelOneGuard.ico",
    "rules/bundled/oneguard_tests.yar",
})


def verify_frozen_assets(executable: Path) -> set[str]:
    """Return required bundled resources that are missing from the CArchive."""
    archive = CArchiveReader(str(executable))
    names = {str(entry).replace("\\", "/") for entry in archive.toc}
    return REQUIRED - names


def main() -> int:
    """Print missing resources and fail the Windows build if any are absent."""
    parser = argparse.ArgumentParser()
    parser.add_argument("executable", type=Path)
    args = parser.parse_args()
    try:
        missing = verify_frozen_assets(args.executable)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"EXE no inspeccionable: {type(exc).__name__}: {exc}")
        return 2
    if missing:
        for name in sorted(missing):
            print(f"FALTA en el EXE: {name}")
        return 1
    print("Recursos SQL / reglas / marca incluidos en el EXE: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
