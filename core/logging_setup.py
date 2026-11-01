"""JSON lines logging with minimal metadata and no credentials."""
import json
import logging
from datetime import datetime, timezone


class JsonFormatter(logging.Formatter):
    """Produce structured log records suitable for local diagnostics."""

    def format(self, record: logging.LogRecord) -> str:
        """Format one record without logging environment variables or API keys."""
        return json.dumps({
            "time": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }, ensure_ascii=False)


def configure_logging() -> None:
    """Install a structured stderr handler if none exists."""
    logger = logging.getLogger("oneguard")
    if logger.handlers:
        return
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
