"""Conservative, explainable indicators shared by Phase 3 engines."""
from __future__ import annotations

import os
import re
from pathlib import Path

_DOUBLE_EXTENSION = re.compile(r"\.(?:pdf|docx?|xlsx?|jpe?g|png|txt)\.(?:exe|scr|com|bat|cmd|js|vbs|ps1)$", re.I)


def has_misleading_extension(name: str) -> bool:
    """Identify executable/script suffixes hidden behind document-looking names."""
    return bool(_DOUBLE_EXTENSION.search(Path(name).name))


def risky_user_location(path: str) -> bool:
    """Detect writable user-profile locations without assuming maliciousness."""
    text = path.replace("/", "\\").lower()
    return any(segment in text for segment in (
        "\\appdata\\local\\temp\\", "\\appdata\\roaming\\",
        "\\appdata\\local\\", "\\downloads\\", "\\users\\public\\",
        "\\temp\\", "\\tmp\\",
    ))


def system_filename_spoof(path: str) -> bool:
    """Flag common spelling imitations; do not use this as an isolated verdict."""
    name = os.path.basename(path.replace("\\", "/")).lower()
    return name in {"svch0st.exe", "expl0rer.exe", "lsasss.exe", "scvhost.exe",
                    "winlogon1.exe", "csrsss.exe", "services1.exe", "sp00lsv.exe"}
