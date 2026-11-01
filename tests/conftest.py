"""Synthetic, harmless test fixtures."""
from pathlib import Path

import pytest

from db.database import SQLiteStore


@pytest.fixture
def store(tmp_path: Path) -> SQLiteStore:
    """Create a fresh SQLite database for each test."""
    return SQLiteStore(tmp_path / "test.db")
