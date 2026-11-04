"""SQLite persistence with thread-local connections per operation."""
from __future__ import annotations

import json
import re
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from core.models import AggregatedFinding, FileHashes, ScanSummary
from core.performance import EngineTiming
from core.archive_members import ArchiveMemberCoverage
from core.system_identity import SystemObservation
from core.file_identity import FileIdentity


_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def utc_now() -> str:
    """Return UTC as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


class SQLiteStore:
    """Store scan sessions, evidence, hashes and privacy-safe reputation entries."""

    def __init__(self, path: Path) -> None:
        """Initialize a writable database and schema."""
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript((Path(__file__).parent / "schema.sql").read_text(encoding="utf-8"))
            # Older user databases require an additive, backward-compatible migration.
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(scan_sessions)")}
            if "omitted_checks" not in columns:
                conn.execute(
                    "ALTER TABLE scan_sessions ADD COLUMN omitted_checks "
                    "INTEGER NOT NULL DEFAULT 0"
                )
            perf_columns = {
                row["name"] for row in conn.execute(
                    "PRAGMA table_info(scan_engine_metrics)"
                )
            }
            for field in ("not_applicable", "not_run"):
                if field not in perf_columns:
                    conn.execute(
                        f"ALTER TABLE scan_engine_metrics ADD COLUMN {field} "
                        "INTEGER NOT NULL DEFAULT 0"
                    )

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        """Create one connection per operation; commit or rollback safely."""
        conn = sqlite3.connect(str(self.path), timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=30000")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def start_session(self, session_id: str) -> None:
        """Register a new scan as running."""
        with self.connection() as conn:
            conn.execute(
                "INSERT INTO scan_sessions(id,started_at,status) VALUES(?,?,?)",
                (session_id, utc_now(), "running"),
            )

    def finish_session(self, summary: ScanSummary) -> None:
        """Record completion state and counters."""
        with self.connection() as conn:
            conn.execute(
                """UPDATE scan_sessions SET finished_at=?, status=?, discovered_files=?,
                   scanned_files=?, finding_files=?, errors=?, omitted_checks=?
                   WHERE id=?""",
                (utc_now(), summary.status.value, summary.discovered_files,
                 summary.scanned_files, summary.finding_files, summary.errors,
                 summary.omitted_checks, summary.session_id),
            )

    def save_engine_metrics(
        self, session_id: str, metrics: dict[str, dict[str, int | float]]
    ) -> None:
        """Persist measured engine timings in a single SQLite transaction."""
        if not metrics:
            return
        with self.connection() as conn:
            conn.executemany(
                """INSERT OR REPLACE INTO scan_engine_metrics
                   (session_id,engine,checks,completed,skipped,errors,
                    duration_seconds,input_size_bytes,signals,not_applicable,not_run)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                [
                    (session_id, engine, int(row.get("checks", 0)),
                     int(row.get("completed", 0)), int(row.get("skipped", 0)),
                     int(row.get("errors", 0)),
                     float(row.get("duration_seconds", 0.0)),
                     int(row.get("input_size_bytes", 0)),
                     int(row.get("signals", 0)),
                     int(row.get("not_applicable", 0)),
                     int(row.get("not_run", 0)))
                    for engine, row in metrics.items()
                ],
            )

    def get_engine_metrics(self, session_id: str) -> list[dict[str, Any]]:
        """Read aggregate engine metrics for a historical scan."""
        with self.connection() as conn:
            return [
                dict(row) for row in conn.execute(
                    """SELECT engine,checks,completed,skipped,errors,
                              duration_seconds,input_size_bytes,signals,
                              not_applicable,not_run
                       FROM scan_engine_metrics WHERE session_id=?
                       ORDER BY duration_seconds DESC""",
                    (session_id,),
                ).fetchall()
            ]

    def record_target(
        self, session_id: str, path: Path, status: str,
        sha256: str | None = None, error: str | None = None,
    ) -> None:
        """Persist the scan outcome of a single target (including errors)."""
        with self.connection() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO scan_targets
                   (session_id,target_path,status,sha256,error) VALUES(?,?,?,?,?)""",
                (session_id, str(path), status, sha256, error),
            )

    def record_target_engine_runs(
        self, session_id: str, path: Path, status: str,
        timings: list[EngineTiming], sha256: str | None = None,
        error: str | None = None,
        archive_members: list[ArchiveMemberCoverage] | None = None,
        system_observation: SystemObservation | None = None,
        file_identity: FileIdentity | None = None,
    ) -> None:
        """Persist target, motors and archive members in one local transaction.

        Inapplicable engines are recorded explicitly, never as successful scans.
        """
        with self.connection() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO scan_targets
                   (session_id,target_path,status,sha256,error) VALUES(?,?,?,?,?)""",
                (session_id, str(path), status, sha256, error),
            )
            if timings:
                conn.executemany(
                    """INSERT OR REPLACE INTO scan_target_engines
                       (session_id,target_path,engine,state,duration_seconds,
                        input_size_bytes,signal_count,reason)
                       VALUES(?,?,?,?,?,?,?,?)""",
                    [
                        (session_id, str(path), timing.engine, timing.status,
                         max(0.0, float(timing.duration_seconds)),
                         max(0, int(timing.input_size_bytes)),
                         max(0, int(timing.signal_count)), timing.reason[:500])
                        for timing in timings
                    ],
                )
            if archive_members:
                conn.executemany(
                    """INSERT OR REPLACE INTO scan_archive_members
                       (session_id,container_path,member_path,archive_format,
                        status,reason,bytes_read,depth,checks_json)
                       VALUES(?,?,?,?,?,?,?,?,?)""",
                    [
                        (session_id, str(path), row.member_path,
                         row.archive_format, row.status, row.reason[:500],
                         max(0, int(row.bytes_read)), max(1, int(row.depth)),
                         json.dumps(row.checks, ensure_ascii=False))
                        for row in archive_members
                    ],
                )

            if file_identity is not None:
                identity = file_identity
                conn.execute(
                    """INSERT OR REPLACE INTO scan_file_identities
                       (session_id,target_path,status,sha256,file_size,bytes_read,
                        elapsed_seconds,reason,observed_at)
                       VALUES(?,?,?,?,?,?,?,?,?)""",
                    (session_id, str(path), identity.status, identity.sha256[:64],
                     identity.file_size, max(0, identity.bytes_read),
                     max(0.0, identity.elapsed_seconds), identity.reason[:500],
                     utc_now()),
                )

            if system_observation is not None:
                row = system_observation
                conn.execute(
                    """INSERT OR REPLACE INTO scan_system_observations
                       (session_id,target_path,kind,status,executable_path,
                        normalized_executable,pid,create_time,source_entry,
                        source_type,command_sha256,note,observed_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (session_id, str(path), row.kind, row.status,
                     row.executable_path[:2048], row.normalized_executable[:2048],
                     row.pid, row.create_time, row.source_entry[:1024],
                     row.source_type[:40], row.command_sha256[:64],
                     row.note[:500], utc_now()),
                )

    def get_file_identities(
        self, session_id: str, *, limit: int = 500
    ) -> list[dict[str, Any]]:
        """Read bounded, session-specific content observations."""
        maximum = max(1, min(int(limit), 2000))
        with self.connection() as conn:
            return [dict(row) for row in conn.execute(
                """SELECT target_path,status,sha256,file_size,bytes_read,
                          elapsed_seconds,reason,observed_at
                   FROM scan_file_identities WHERE session_id=?
                   ORDER BY target_path LIMIT ?""",
                (session_id, maximum),
            ).fetchall()]

    def get_system_observations(
        self, session_id: str, *, limit: int = 500
    ) -> list[dict[str, Any]]:
        """Read bounded identity metadata, not raw autostart command lines."""
        maximum = max(1, min(int(limit), 2000))
        with self.connection() as conn:
            return [dict(row) for row in conn.execute(
                """SELECT target_path,kind,status,executable_path,pid,
                          create_time,source_entry,source_type,command_sha256,
                          note,observed_at FROM scan_system_observations
                   WHERE session_id=? ORDER BY kind,target_path LIMIT ?""",
                (session_id, maximum),
            ).fetchall()]

    def get_archive_members(
        self, session_id: str, container: Path | str, *, limit: int = 500
    ) -> list[dict[str, Any]]:
        """Return a bounded local-only view of member coverage evidence."""
        maximum = max(1, min(int(limit), 1000))
        with self.connection() as conn:
            rows = conn.execute(
                """SELECT member_path,archive_format,status,reason,
                          bytes_read,depth,checks_json
                   FROM scan_archive_members
                   WHERE session_id=? AND container_path=?
                   ORDER BY depth, member_path LIMIT ?""",
                (session_id, str(container), maximum),
            ).fetchall()
        return [
            {**dict(row), "checks": json.loads(row["checks_json"])}
            for row in rows
        ]

    def get_target_engine_runs(
        self, session_id: str, path: Path | str
    ) -> list[dict[str, Any]]:
        """Read the actual inspection status of each motor for one target."""
        with self.connection() as conn:
            return [
                dict(row) for row in conn.execute(
                    """SELECT engine,state,duration_seconds,input_size_bytes,
                              signal_count,reason
                       FROM scan_target_engines
                       WHERE session_id=? AND target_path=?
                       ORDER BY engine""",
                    (session_id, str(path)),
                ).fetchall()
            ]

    def get_recent_target_paths(self, session_id: str, limit: int = 250) -> list[str]:
        """Get a bounded list for local GUI evidence drilldown."""
        count = max(1, min(int(limit), 500))
        with self.connection() as conn:
            return [
                str(row["target_path"])
                for row in conn.execute(
                    """SELECT target_path FROM scan_targets WHERE session_id=?
                       ORDER BY rowid DESC LIMIT ?""",
                    (session_id, count),
                ).fetchall()
            ]

    def record_coverage(
        self, session_id: str, path: Path, engine: str, code: str,
        params: dict[str, Any], detail: str,
    ) -> None:
        """Persist an omitted engine check without implying a malware finding."""
        with self.connection() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO scan_coverage
                   (session_id,target_path,engine,event_code,params_json,detail,recorded_at)
                   VALUES(?,?,?,?,?,?,?)""",
                (session_id, str(path), engine, code,
                 json.dumps(params, ensure_ascii=False, default=str),
                 detail, utc_now()),
            )

    def save_finding(self, session_id: str, finding: AggregatedFinding) -> None:
        """Save the full verdict and every piece of contributing evidence."""
        with self.connection() as conn:
            cursor = conn.execute(
                """INSERT INTO findings
                   (session_id,target_path,threat_type,severity,risk_score,confidence,
                    reason,sha256,suppressed,engines_json,created_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (session_id, finding.target, finding.threat_type,
                 finding.severity.value, finding.risk_score, finding.confidence,
                 finding.reason, finding.sha256, int(finding.suppressed),
                 json.dumps(finding.engines), utc_now()),
            )
            finding_id = cursor.lastrowid
            for signal in finding.evidence:
                conn.execute(
                    """INSERT INTO evidence
                       (finding_id,engine,rule_id,reason,risk_score,confidence,details_json)
                       VALUES(?,?,?,?,?,?,?)""",
                    (finding_id, signal.engine, signal.rule_id, signal.reason,
                     signal.risk_score, signal.confidence,
                     json.dumps(signal.details, ensure_ascii=False, default=str)),
                )

    def add_hash_signature(
        self, sha256: str, name: str, threat_type: str, reason: str,
        risk_score: int = 95, confidence: int = 95,
        source: str = "manual",
    ) -> None:
        """Import an explicitly reviewed SHA-256 signature."""
        sha256 = sha256.lower()
        if not _SHA256.fullmatch(sha256):
            raise ValueError("SHA-256 inválido")
        if not (0 <= risk_score <= 100 and 0 <= confidence <= 100):
            raise ValueError("Puntuación fuera de rango")
        with self.connection() as conn:
            conn.execute(
                """INSERT INTO hash_signatures VALUES(?,?,?,?,?,?,?,?)
                   ON CONFLICT(sha256) DO UPDATE SET
                   name=excluded.name,threat_type=excluded.threat_type,
                   reason=excluded.reason,risk_score=excluded.risk_score,
                   confidence=excluded.confidence,source=excluded.source""",
                (sha256, name, threat_type, reason, risk_score, confidence,
                 source, utc_now()),
            )

    def get_hash_signature(self, sha256: str) -> dict[str, Any] | None:
        """Retrieve a known local signature by digest."""
        with self.connection() as conn:
            result = conn.execute(
                "SELECT * FROM hash_signatures WHERE sha256=?", (sha256.lower(),)
            ).fetchone()
            return dict(result) if result is not None else None

    def get_cached_file(self, path: Path, stat: Any) -> FileHashes | None:
        """Reuse a digest only when all available file identity fields agree."""
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM file_cache WHERE target_path=?", (str(path),)
            ).fetchone()
            if row is None:
                return None
            fingerprint = (
                int(stat.st_size), int(stat.st_mtime_ns), int(stat.st_ctime_ns),
                int(stat.st_ino), int(stat.st_dev),
            )
            cached = tuple(row[k] for k in ("size", "mtime_ns", "ctime_ns", "inode", "device"))
            if fingerprint != cached:
                return None
            return FileHashes(row["sha256"], row["md5"], row["size"])

    def cache_file(self, path: Path, stat: Any, hashes: FileHashes) -> None:
        """Cache only fully computed hashes of a stable file."""
        with self.connection() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO file_cache VALUES(?,?,?,?,?,?,?,?,?)""",
                (str(path), int(stat.st_size), int(stat.st_mtime_ns),
                 int(stat.st_ctime_ns), int(stat.st_ino), int(stat.st_dev),
                 hashes.sha256, hashes.md5, utc_now()),
            )

    def get_reputation_cache(
        self, provider: str, sha256: str, ttl_seconds: int
    ) -> dict[str, Any] | None:
        """Return a fresh cached API response, excluding any authentication info."""
        with self.connection() as conn:
            row = conn.execute(
                "SELECT * FROM reputation_cache WHERE provider=? AND sha256=?",
                (provider, sha256),
            ).fetchone()
            if row is None or time.time() - row["checked_ts"] > ttl_seconds:
                return None
            return {"status": row["status"], "data": json.loads(row["response_json"])}

    def save_reputation_cache(
        self, provider: str, sha256: str, status: str, data: dict[str, Any]
    ) -> None:
        """Persist only selected, normalized fields of a reputation response."""
        with self.connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO reputation_cache VALUES(?,?,?,?,?,?)",
                (provider, sha256, status, json.dumps(data), utc_now(), time.time()),
            )

    def reserve_daily_request(self, provider: str, maximum: int) -> bool:
        """Atomically reserve one daily call, including across concurrent workers."""
        day = datetime.now(timezone.utc).date().isoformat()
        with self.connection() as conn:
            result = conn.execute(
                """INSERT INTO api_quotas(provider,utc_day,requests) VALUES(?,?,1)
                   ON CONFLICT(provider,utc_day) DO UPDATE SET requests=requests+1
                   WHERE requests < ?""",
                (provider, day, maximum),
            )
            return result.rowcount == 1

    def is_whitelisted(self, sha256: str) -> bool:
        """Check user-approved exclusions by content fingerprint, not filename."""
        with self.connection() as conn:
            return conn.execute(
                "SELECT 1 FROM whitelist WHERE sha256=?", (sha256,)
            ).fetchone() is not None


    def add_whitelist_entry(self, finding_id: int, reason: str, *, confirmation: str) -> str:
        """Explicitly suppress a reviewed SHA-256, without deleting evidence."""
        from core.remediation_policy import RemediationDenied, require_approval
        import json
        require_approval(confirmation, "IGNORAR HASH")
        if not reason.strip():
            raise RemediationDenied("Se requiere un motivo de exclusión")
        with self.connection() as conn:
            finding = conn.execute("SELECT sha256 FROM findings WHERE id=?", (finding_id,)).fetchone()
            if finding is None or not finding["sha256"] or not _SHA256.fullmatch(finding["sha256"].lower()):
                raise RemediationDenied("No hay SHA-256 verificado para excluir")
            digest = finding["sha256"].lower()
            conn.execute("INSERT OR REPLACE INTO whitelist VALUES(?,?,?)",
                         (digest, reason[:300], utc_now()))
            # Preserve historical evidence but mark this verdict as suppressed.
            conn.execute("UPDATE findings SET suppressed=1 WHERE id=?", (finding_id,))
            conn.execute("INSERT INTO audit_log(event,detail_json,at) VALUES(?,?,?)",
                         ("whitelist_added", json.dumps({"finding_id": finding_id,
                                                           "sha256": digest}), utc_now()))
        return digest
