# -*- mode: python ; coding: utf-8 -*-
"""Windows one-file GUI build with branded icon, Qt libraries and bundled rules.

Run from the project root on Windows:
    py -3.11 -m PyInstaller --clean --noconfirm build.spec
"""
from pathlib import Path
import os

from PyInstaller.utils.hooks import collect_submodules

root = Path(SPECPATH)

# Oletools imports specialized parsers during macro inspection; explicitly
# collect them even when Python sees imports only inside a scanner method.
macro_imports = collect_submodules('oletools')

analysis = Analysis(
    [str(root / 'run_gui.py')],
    pathex=[str(root)],
    binaries=[],
    datas=[
        (str(root / 'assets'), 'assets'),
        (str(root / 'rules' / 'bundled'), 'rules/bundled'),
    ],
    hiddenimports=macro_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'IPython', 'pytest'],
    noarchive=False,
)

pyz = PYZ(analysis.pure)

exe = EXE(
    pyz,
    analysis.scripts,
    analysis.binaries,
    analysis.datas,
    [],
    name='SentinelOneGuard',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    icon=str(root / 'assets' / 'SentinelOneGuard.ico'),
    version=str(root / 'windows_version_info.txt'),
    uac_admin=os.environ.get('ONEGUARD_REQUIRE_ADMIN', '1') == '1',
    disable_windowed_traceback=False,
)
