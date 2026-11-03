"""Errors distinguish unavailable analysis from a negative detection result."""


class ScanSkipped(Exception):
    """An intentional omission, with optional machine-readable coverage details."""

    def __init__(
        self, message: str, *, code: str = "SCAN.ENGINE.SKIPPED",
        params: dict | None = None,
    ) -> None:
        """Preserve legacy text for logs and typed details for the UI."""
        super().__init__(message)
        self.code = code
        self.params = dict(params or {})


class FileChangedDuringScan(OSError):
    """A file was modified or replaced during content hashing."""


class RuleLoadError(RuntimeError):
    """YARA rules could not be compiled safely."""
