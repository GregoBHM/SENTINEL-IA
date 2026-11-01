"""Errors distinguish unavailable analysis from a negative detection result."""


class ScanSkipped(Exception):
    """An engine deliberately skipped the target due to a configured limitation."""


class FileChangedDuringScan(OSError):
    """A file was modified or replaced during content hashing."""


class RuleLoadError(RuntimeError):
    """YARA rules could not be compiled safely."""
