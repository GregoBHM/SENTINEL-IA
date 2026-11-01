"""Small, bounded, read-only presentation queries for existing SQLite findings."""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class FindingRow:
    """A persisted verdict displayed in the results table."""

    id: int
    session_id: str
    target: str
    threat_type: str
    severity: str
    score: int
    confidence: int
    reason: str
    engines: tuple[str, ...]
    sha256: str | None
    suppressed: bool
    timestamp: str


@dataclass(frozen=True, slots=True)
class SessionRow:
    """Summary of a previous scan persisted in SQLite."""

    id: str
    started: str
    finished: str | None
    status: str
    scanned: int
    finding_files: int
    errors: int


class HistoryRepository:
    """Read bounded pages from SQLite without running write SQL from the GUI."""

    def __init__(self, db_path: Path) -> None:
        self.path = Path(db_path)

    def _fetch(self, query: str, parameters: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        """Fetch read-only rows with short busy timeout for GUI responsiveness."""
        connection = sqlite3.connect(str(self.path), timeout=0.25)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA query_only=ON")
            return connection.execute(query, parameters).fetchall()
        finally:
            connection.close()

    def sessions(self, limit: int = 100) -> list[SessionRow]:
        """Return newest sessions within a fixed UI page size."""
        return [SessionRow(
            id=row["id"], started=row["started_at"], finished=row["finished_at"],
            status=row["status"], scanned=row["scanned_files"],
            finding_files=row["finding_files"], errors=row["errors"],
        ) for row in self._fetch(
            "SELECT * FROM scan_sessions ORDER BY started_at DESC LIMIT ?",
            (max(1, min(limit, 500)),),
        )]

    def findings(self, session_id: str, limit: int = 2500) -> list[FindingRow]:
        """Return persisted findings without loading unbounded history into memory."""
        return [FindingRow(
            id=int(row["id"]), session_id=row["session_id"],
            target=row["target_path"], threat_type=row["threat_type"],
            severity=row["severity"], score=int(row["risk_score"]),
            confidence=int(row["confidence"]), reason=row["reason"],
            engines=tuple(json.loads(row["engines_json"])), sha256=row["sha256"],
            suppressed=bool(row["suppressed"]), timestamp=row["created_at"],
        ) for row in self._fetch(
            "SELECT * FROM findings WHERE session_id=? ORDER BY risk_score DESC, id DESC LIMIT ?",
            (session_id, max(1, min(limit, 5000))),
        )]

    def evidence(self, finding_id: int) -> list[dict[str, Any]]:
        """Return raw evidence for one explicitly selected verdict."""
        result = []
        for row in self._fetch(
            "SELECT engine,rule_id,reason,risk_score,confidence,details_json "
            "FROM evidence WHERE finding_id=? ORDER BY id LIMIT 200", (finding_id,),
        ):
            entry = dict(row)
            try:
                entry["details"] = json.loads(entry.pop("details_json"))
            except ValueError:
                entry["details"] = {"warning": "Metadatos no disponibles"}
            result.append(entry)
        return result

    def quarantine_items(self, limit: int = 200) -> list[dict[str, Any]]:
        """List quarantine metadata without exposing or touching blob contents."""
        return [dict(row) for row in self._fetch(
            "SELECT id,original_path,sha256,size,status,created_at,last_error "
            "FROM quarantine_items ORDER BY created_at DESC LIMIT ?",
            (max(1, min(limit, 500)),),
        )]

    def disabled_autoruns(self, limit: int = 200) -> list[dict[str, Any]]:
        """List backed-up HKCU startup entries without exposing command contents."""
        return [dict(row) for row in self._fetch(
            "SELECT id,hive,key_path,value_name,status,created_at FROM disabled_autoruns "
            "ORDER BY created_at DESC LIMIT ?", (max(1, min(limit, 500)),),
        )]
