"""Local configuration; credentials are read only from environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def data_directory() -> Path:
    """Select a per-user writable directory without hardcoding Windows profiles."""
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", str(Path.home())))
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local/share")))
    return base / "SentinelOneGuard"


@dataclass(frozen=True, slots=True)
class ScanConfig:
    """Bounded scan settings shared by the CLI and future graphical wizard."""

    database_path: Path = field(default_factory=lambda: data_directory() / "oneguard.db")
    rule_directory: Path = field(
        default_factory=lambda: Path(__file__).resolve().parents[1] / "rules" / "bundled"
    )
    exclusions: tuple[Path, ...] = ()
    max_workers: int = 3
    max_pending: int = 12
    yara_max_file_size: int = 64 * 1024 * 1024
    yara_timeout_seconds: int = 20
    online_consent: bool = False
    online_enabled: bool = False
    vt_api_key: str = field(default_factory=lambda: os.environ.get("ONEGUARD_VT_API_KEY", ""))
    mb_api_key: str = field(default_factory=lambda: os.environ.get("ONEGUARD_MB_API_KEY", ""))
    reputation_ttl_seconds: int = 7 * 86400
    pe_max_file_size: int = 128 * 1024 * 1024
    script_max_bytes: int = 2 * 1024 * 1024
    archive_max_depth: int = 3
    archive_max_entries: int = 10000
    archive_max_total_bytes: int = 64 * 1024 * 1024
    archive_max_member_bytes: int = 8 * 1024 * 1024
    archive_timeout_seconds: int = 60

    def __post_init__(self) -> None:
        """Guard against unbounded or contradictory configurations."""
        if not 1 <= self.max_workers <= 32:
            raise ValueError("max_workers debe estar entre 1 y 32")
        if self.max_pending < self.max_workers:
            raise ValueError("max_pending debe ser >= max_workers")
        if self.yara_timeout_seconds < 1 or self.yara_max_file_size < 1:
            raise ValueError("Los límites YARA deben ser positivos")
        if not (1 <= self.archive_max_depth <= 10 and
                1 <= self.archive_max_entries <= 100000 and
                0 < self.archive_max_member_bytes <= self.archive_max_total_bytes <= 1024**3 and
                1 <= self.archive_timeout_seconds <= 600 and
                self.pe_max_file_size > 0 and self.script_max_bytes > 0):
            raise ValueError("Límites PE, scripts o comprimidos inválidos")
        if self.online_enabled and not self.online_consent:
            raise ValueError("Se requiere consentimiento explícito para consultas en línea")


def load_config_file(path: Path) -> ScanConfig:
    """Load optional TOML settings; never accept API keys from a plain-text file."""
    import tomllib

    source = Path(path).expanduser().absolute()
    with source.open("rb") as handle:
        raw = tomllib.load(handle)
    if not isinstance(raw, dict):
        raise ValueError("La configuración TOML debe ser una tabla")
    allowed_sections = {"scanner", "paths"}
    unknown_sections = set(raw) - allowed_sections
    if unknown_sections:
        raise ValueError(f"Secciones no reconocidas: {sorted(unknown_sections)}")
    scanner = raw.get("scanner", {})
    paths = raw.get("paths", {})
    if not isinstance(scanner, dict) or not isinstance(paths, dict):
        raise ValueError("Las secciones scanner/paths deben ser tablas")
    allowed_scanner = {"max_workers", "max_pending", "yara_max_file_size_mb",
                       "yara_timeout_seconds", "exclusions", "pe_max_file_size_mb",
                       "script_max_bytes_mb", "archive_max_depth", "archive_max_entries",
                       "archive_max_total_bytes_mb", "archive_max_member_bytes_mb",
                       "archive_timeout_seconds"}
    allowed_paths = {"database", "rules"}
    if set(scanner) - allowed_scanner or set(paths) - allowed_paths:
        raise ValueError("Clave de configuración desconocida")
    if not isinstance(scanner.get("exclusions", []), list):
        raise ValueError("scanner.exclusions debe ser una lista")
    defaults = ScanConfig()
    return ScanConfig(
        database_path=Path(paths.get("database", defaults.database_path)).expanduser(),
        rule_directory=Path(paths.get("rules", defaults.rule_directory)).expanduser(),
        exclusions=tuple(Path(s).expanduser() for s in scanner.get("exclusions", [])),
        max_workers=int(scanner.get("max_workers", defaults.max_workers)),
        max_pending=int(scanner.get("max_pending", defaults.max_pending)),
        yara_max_file_size=int(scanner.get("yara_max_file_size_mb", 64)) * 1024 * 1024,
        yara_timeout_seconds=int(scanner.get(
            "yara_timeout_seconds", defaults.yara_timeout_seconds
        )),
        pe_max_file_size=int(scanner.get("pe_max_file_size_mb", 128)) * 1024**2,
        script_max_bytes=int(scanner.get("script_max_bytes_mb", 2)) * 1024**2,
        archive_max_depth=int(scanner.get("archive_max_depth", defaults.archive_max_depth)),
        archive_max_entries=int(scanner.get("archive_max_entries", defaults.archive_max_entries)),
        archive_max_total_bytes=int(scanner.get("archive_max_total_bytes_mb", 64)) * 1024**2,
        archive_max_member_bytes=int(scanner.get("archive_max_member_bytes_mb", 8)) * 1024**2,
        archive_timeout_seconds=int(scanner.get("archive_timeout_seconds", 60)),
    )
