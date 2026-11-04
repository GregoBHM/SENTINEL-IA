"""Read-only, auditable relationships derived exclusively from local scan data.

These are observations and bookkeeping relations, not an attack graph or proof
of causation. File names, local paths and hashes never leave this process.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from db.database import SQLiteStore


@dataclass(frozen=True, slots=True)
class TraceRelation:
    """One supported relationship and where it came from."""

    source: str
    relation: str
    target: str
    evidence: str
    kind: str


@dataclass(frozen=True, slots=True)
class EvidenceTrace:
    """Bounded result for a single session with explicit sampling limits."""

    session_id: str
    relations: tuple[TraceRelation, ...]
    truncated: bool
    limitations: tuple[str, ...]


def _clean(value: object, limit: int = 500) -> str:
    """Bound stored labels, which may originate from untrusted filenames."""
    return str(value if value is not None else "").replace("\x00", "")[:limit]


def read_evidence_trace(
    store: "SQLiteStore", session_id: str, *, limit: int = 250,
) -> EvidenceTrace:
    """Read observed relations for one session, without scanning or inferring origin.

    Only links supported by persisted findings, engine evidence, archive member
    metadata, omissions, or identical SHA-256 are emitted. Query limits protect
    the GUI from large sessions; a truncated report does not claim full coverage.
    """
    if not session_id:
        raise ValueError("Se requiere el identificador de sesión")
    maximum = max(1, min(int(limit), 500))
    relations: list[TraceRelation] = []
    seen: set[tuple[str, str, str, str]] = set()

    def add(source: str, relation: str, target: str, evidence: str, kind: str) -> None:
        key = (source, relation, target, evidence)
        if key not in seen:
            relations.append(TraceRelation(
                _clean(source), relation, _clean(target), _clean(evidence), kind
            ))
            seen.add(key)

    with store.connection() as conn:
        # Fetch one extra row per bounded table to detect truncation truthfully.
        records = conn.execute(
            """SELECT id,target_path,threat_type,severity,risk_score,suppressed
               FROM findings WHERE session_id=?
               ORDER BY risk_score DESC, id DESC LIMIT ?""",
            (session_id, maximum + 1),
        ).fetchall()
        truncated = len(records) > maximum
        records = records[:maximum]
        for row in records:
            fid = int(row["id"])
            add(
                row["target_path"], "Tiene hallazgo",
                f"#{fid} · {row['threat_type']}",
                f"Persistido · {row['severity']} · riesgo orientativo "
                f"{row['risk_score']}/100"
                + (" · suprimido" if row["suppressed"] else ""),
                "finding",
            )

        if records:
            placeholders = ",".join("?" for _ in records)
            evidence_rows = conn.execute(
                f"""SELECT id,finding_id,engine,rule_id,reason,details_json
                    FROM evidence WHERE finding_id IN ({placeholders})
                    ORDER BY id LIMIT ?""",
                (*[int(row["id"]) for row in records], maximum + 1),
            ).fetchall()
            truncated |= len(evidence_rows) > maximum
            matching = {int(row["id"]): str(row["target_path"]) for row in records}
            for item in evidence_rows[:maximum]:
                source = matching[int(item["finding_id"])]
                label = (
                    f"{item['engine']} · {item['rule_id'] or 'sin regla'}"
                )
                add(
                    source, "Evidencia del motor", label,
                    f"evidence#{item['id']}: {_clean(item['reason'], 300)}",
                    "engine",
                )
                try:
                    details = json.loads(item["details_json"])
                except (ValueError, TypeError):
                    details = {}
                if not isinstance(details, dict):
                    details = {}
                executable = details.get("executable_path")
                if isinstance(executable, str) and executable.strip():
                    # This is a path reported by an engine, not verified process
                    # execution, infection source or a current running process.
                    add(
                        source, "Ruta declarada por motor",
                        executable,
                        f"{item['engine']} · evidence#{item['id']} · no implica ejecución actual",
                        "context",
                    )

        members = conn.execute(
            """SELECT container_path,member_path,status,reason,depth,checks_json
               FROM scan_archive_members WHERE session_id=?
               ORDER BY container_path,depth,member_path LIMIT ?""",
            (session_id, maximum + 1),
        ).fetchall()
        truncated |= len(members) > maximum
        for row in members[:maximum]:
            child = str(row["member_path"])
            container = str(row["container_path"])
            if child == container:
                continue
            parent = child.rpartition("::")[0]
            if not parent.startswith(container):
                parent = container
            checks = ""
            try:
                decoded = json.loads(row["checks_json"])
                if isinstance(decoded, list):
                    checks = ", ".join(str(x)[:40] for x in decoded[:10])
            except (TypeError, ValueError):
                pass
            add(
                parent, "Contiene entrada enumerada", child,
                f"{row['status']} · profundidad {row['depth']}"
                + (f" · {_clean(row['reason'], 160)}" if row["reason"] else "")
                + (f" · comprobaciones: {checks}" if checks else ""),
                "archive",
            )

        omissions = conn.execute(
            """SELECT target_path,engine,event_code,detail FROM scan_coverage
               WHERE session_id=? ORDER BY target_path LIMIT ?""",
            (session_id, maximum + 1),
        ).fetchall()
        truncated |= len(omissions) > maximum
        for row in omissions[:maximum]:
            add(
                row["target_path"], "Comprobación limitada",
                f"{row['engine']} · {row['event_code']}",
                row["detail"], "coverage",
            )

        # A relation is justified only by a verified PID + creation time and
        # a direct, unambiguous configured executable reference at this scan.
        # Equal paths do NOT establish who launched the process.
        system_links = conn.execute(
            """SELECT p.target_path AS process_target, p.pid, p.create_time,
                      p.observed_at, p.executable_path,
                      a.target_path AS autorun_target, a.source_entry,
                      a.source_type, a.observed_at AS autorun_observed_at
               FROM scan_system_observations p
               JOIN scan_system_observations a
                 ON p.session_id=a.session_id
                AND p.normalized_executable=a.normalized_executable
               WHERE p.session_id=? AND p.kind='process'
                 AND p.status='verified' AND p.pid IS NOT NULL
                 AND p.create_time IS NOT NULL
                 AND a.kind='persistence' AND a.status='reference_only'
                 AND p.normalized_executable!=''
               ORDER BY p.target_path,a.target_path LIMIT ?""",
            (session_id, maximum + 1),
        ).fetchall()
        truncated |= len(system_links) > maximum
        for row in system_links[:maximum]:
            add(
                row["source_entry"] or row["autorun_target"],
                "Ruta coincidente con proceso observado",
                row["process_target"],
                f"PID {row['pid']} · creación {row['create_time']} · "
                f"ejecutable {row['executable_path']} · "
                f"origen {row['source_type']} · instantánea {row['observed_at']}. "
                "No demuestra que esta entrada iniciara el proceso.",
                "system_link",
            )

        # Incomplete identity is a coverage limit, not evidence of maliciousness.
        incomplete_system = conn.execute(
            """SELECT target_path,kind,status,note FROM scan_system_observations
               WHERE session_id=? AND status IN (
                 'stale','unavailable','incomplete','ambiguous'
               ) ORDER BY target_path LIMIT ?""",
            (session_id, min(maximum, 60) + 1),
        ).fetchall()
        truncated |= len(incomplete_system) > min(maximum, 60)
        for row in incomplete_system[:min(maximum, 60)]:
            add(
                row["target_path"], "Identidad o comando no correlacionable",
                f"{row['kind']} · {row['status']}",
                row["note"] or "No hay una identidad fiable disponible",
                "identity_limit",
            )

        # Content identity is evidence of the disk bytes we read, not the
        # mapped process image or evidence that a file is safe.
        file_identities = conn.execute(
            """SELECT target_path,status,sha256,file_size,bytes_read,reason
               FROM scan_file_identities WHERE session_id=?
               ORDER BY target_path LIMIT ?""",
            (session_id, maximum + 1),
        ).fetchall()
        truncated |= len(file_identities) > maximum
        for row in file_identities[:maximum]:
            if row["status"] == "observed":
                add(
                    row["target_path"], "Huella de contenido observada",
                    str(row["sha256"])[:64],
                    f"SHA-256 de {row['bytes_read']} bytes leídos en disco; "
                    "no identifica los bytes cargados en memoria ni confirma seguridad.",
                    "content_identity",
                )
            else:
                add(
                    row["target_path"], "Identidad de contenido incompleta",
                    str(row["status"]),
                    str(row["reason"])[:300],
                    "identity_limit",
                )

        # An identical content hash is a demonstrable relation, but never a
        # claim of propagation or related infection. Keep only bounded pairs.
        hashes = conn.execute(
            """SELECT target_path,sha256 FROM scan_targets
               WHERE session_id=? AND sha256 IS NOT NULL
               ORDER BY sha256,target_path LIMIT ?""",
            (session_id, maximum + 1),
        ).fetchall()
        truncated |= len(hashes) > maximum
        by_hash: dict[str, str] = {}
        for item in hashes[:maximum]:
            digest = str(item["sha256"]).lower()
            if len(digest) != 64 or any(x not in "0123456789abcdef" for x in digest):
                continue
            path = str(item["target_path"])
            other = by_hash.get(digest)
            if other and other != path:
                add(
                    other, "SHA-256 idéntico", path,
                    f"{digest[:16]}… · mismos bytes según registro; "
                    "no implica propagación",
                    "hash",
                )
            else:
                by_hash[digest] = path

    if len(relations) > maximum:
        truncated = True
    return EvidenceTrace(
        session_id, tuple(relations[:maximum]), truncated,
        (
            "Las relaciones proceden de una sesión local y no prueban causalidad.",
            "Una ruta declarada por un sensor no confirma ejecución actual ni el punto de entrada.",
            "Una ruta coincidente entre inicio y proceso no demuestra que el inicio lo haya ejecutado.",
            "Ausencia de hallazgos no demuestra equipo limpio; revisar omisiones y motores no disponibles.",
            "La lista está limitada para proteger la interfaz; puede omitir relaciones adicionales.",
        ),
    )
