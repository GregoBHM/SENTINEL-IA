"""Conservative path and explicit-authorization policy for remediation.

No path supplied by a scan or user is assumed safe, especially with UAC enabled.
This is a fail-closed policy, not a guarantee against local privileged races.
"""
from __future__ import annotations

import os
import re
import stat
from pathlib import Path


class RemediationDenied(ValueError):
    """The requested action violates a safety rule or lacks approval."""


def require_approval(actual: str, required: str) -> None:
    """Require a distinct, explicit confirmation string for each action."""
    if actual != required:
        raise RemediationDenied(f"Se requiere confirmación exacta: {required}")


def _within(path: Path, parent: Path) -> bool:
    """Check path ancestry component-wise; never compare string prefixes."""
    return path == parent or parent in path.parents


def _reject_reparse_chain(path: Path) -> None:
    """Reject symbolic links, junctions and reparse components even in ancestors."""
    chain = (path, *path.parents)
    for component in chain:
        if not component.exists() and not component.is_symlink():
            continue
        if component.is_symlink() or (hasattr(component, "is_junction") and
                                      component.is_junction()):
            raise RemediationDenied("Ruta con enlace simbólico o junction")
        try:
            attrs = getattr(component.lstat(), "st_file_attributes", 0)
        except OSError as exc:
            raise RemediationDenied("No se puede verificar la ruta") from exc
        if os.name == "nt" and attrs & 0x400:
            raise RemediationDenied("Ruta con punto de reanálisis (reparse point)")


def validate_mutable_file(path: Path, *, vault: Path | None = None) -> Path:
    """Permit only ordinary unlinked local files outside protected system paths.

    This check is repeated immediately before each mutation. It deliberately
    refuses files with multiple hard links and files under protected locations.
    """
    candidate = Path(path).expanduser().absolute()
    value = str(candidate)
    if os.name == "nt":
        if (value.startswith("\\\\") or value.startswith("\\\\?\\") or
                re.match(r"^[A-Za-z]:", value) is None or
                ":" in value[2:]):
            raise RemediationDenied("No se permiten rutas UNC, dispositivos ni ADS")
    _reject_reparse_chain(candidate)
    try:
        info = candidate.lstat()
    except OSError as exc:
        raise RemediationDenied("Archivo no disponible") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise RemediationDenied("Solo archivos regulares sin hard links")
    actual = candidate.resolve(strict=True)
    if vault is not None and _within(actual, vault.resolve(strict=False)):
        raise RemediationDenied("No se modifica el almacenamiento de cuarentena por ruta externa")
    if os.name == "nt":
        windows = Path(os.environ.get("SystemRoot", "C:\\Windows")).resolve(strict=False)
        protected = [windows]
        for env in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "PROGRAMDATA"):
            if os.environ.get(env):
                protected.append(Path(os.environ[env]).resolve(strict=False))
        if any(_within(actual, root) for root in protected):
            raise RemediationDenied("Ubicación del sistema o de programas protegida")
    else:
        protected = [Path(s) for s in ("/usr", "/bin", "/sbin", "/etc", "/lib", "/lib64", "/boot", "/var", "/opt")]
        if any(_within(actual, root) for root in protected):
            raise RemediationDenied("Ubicación protegida")
    return actual


def sha256_file(path: Path) -> tuple[str, int]:
    """Calculate SHA-256 without loading the file into memory."""
    import hashlib

    digest = hashlib.sha256()
    total = 0
    with Path(path).open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
            total += len(chunk)
    return digest.hexdigest(), total


def validate_restore_parent(path: Path, *, vault: Path) -> Path:
    """Verify the absent restore destination and its real unprotected parent."""
    original = Path(path).expanduser().absolute()
    if original.exists() or original.is_symlink():
        raise RemediationDenied("El destino ya existe; no se sobrescribirá")
    if os.name == "nt" and (str(original).startswith("\\\\") or
                            re.match(r"^[A-Za-z]:", str(original)) is None or
                            ":" in str(original)[2:]):
        raise RemediationDenied("Ruta de destino no admitida")
    parent = original.parent
    _reject_reparse_chain(parent)
    if not parent.is_dir():
        raise RemediationDenied("La carpeta original ya no existe")
    actual_parent = parent.resolve(strict=True)
    if _within(actual_parent, vault.resolve(strict=True)):
        raise RemediationDenied("No se restaurará dentro de la cuarentena")
    if os.name == "nt":
        roots = [Path(os.environ.get("SystemRoot", r"C:\Windows"))]
        for key in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "PROGRAMDATA"):
            if os.environ.get(key):
                roots.append(Path(os.environ[key]))
        if any(_within(actual_parent, root.resolve(strict=False)) for root in roots):
            raise RemediationDenied("Restauración sobre directorio protegido")
    else:
        if any(_within(actual_parent, Path(root)) for root in
               ("/usr", "/bin", "/sbin", "/etc", "/lib", "/lib64", "/boot", "/var", "/opt")):
            raise RemediationDenied("Restauración sobre directorio protegido")
    return original
