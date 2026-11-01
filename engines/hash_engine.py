"""SHA-256 local signature and optional reputation detection."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

from core.aggregator import severity_from_score
from core.detection_engine import DetectionEngine
from core.errors import FileChangedDuringScan
from core.models import FileHashes, Finding, ScanTarget
from core.reputation_client import ReputationClient
from db.database import SQLiteStore


class HashEngine(DetectionEngine):
    """Read targets in blocks; use cryptographic hashes, never execute files."""

    name = "hash"

    def __init__(
        self, store: SQLiteStore, reputation: ReputationClient | None = None,
    ) -> None:
        """Bind local signatures, reusable hash cache and optional reputation."""
        self.store = store
        self.reputation = reputation

    def compute_hashes(self, path: Path) -> FileHashes:
        """Stream SHA-256 and MD5 with before/after metadata consistency checks."""
        path = Path(path).absolute()
        before = path.stat()
        cached = self.store.get_cached_file(path, before)
        if cached is not None:
            return cached
        sha256 = hashlib.sha256()
        md5 = hashlib.md5(usedforsecurity=False)
        with path.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            if self._fingerprint(opened) != self._fingerprint(before):
                raise FileChangedDuringScan(f"Archivo sustituido antes de leer: {path}")
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                sha256.update(chunk)
                md5.update(chunk)
            after_handle = os.fstat(handle.fileno())
        after_path = path.stat()
        if (self._fingerprint(before) != self._fingerprint(after_handle)
                or self._fingerprint(before) != self._fingerprint(after_path)):
            raise FileChangedDuringScan(f"Archivo modificado durante lectura: {path}")
        digests = FileHashes(sha256.hexdigest(), md5.hexdigest(), before.st_size)
        self.store.cache_file(path, before, digests)
        return digests

    @staticmethod
    def _fingerprint(stat: os.stat_result) -> tuple[int, int, int, int, int]:
        """Use metadata that is available on Windows and UNIX filesystems."""
        return (stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns,
                stat.st_ino, stat.st_dev)

    def scan(self, target: ScanTarget) -> list[Finding]:
        """Return known local and opt-in external matches for one file."""
        if target.kind != "file":
            return []
        hashes = self.compute_hashes(target.path)
        path = str(target.path)
        findings: list[Finding] = []
        signature = self.store.get_hash_signature(hashes.sha256)
        if signature is not None:
            score = int(signature["risk_score"])
            findings.append(Finding(
                target=path, engine=self.name,
                threat_type=signature["threat_type"],
                reason=signature["reason"],
                severity=severity_from_score(score),
                risk_score=score,
                confidence=int(signature["confidence"]),
                rule_id=signature["name"],
                evidence_group="sha256_signature",
                sha256=hashes.sha256,
                details={"source": signature["source"]},
            ))
        if self.reputation is not None:
            for verdict in self.reputation.check(hashes.sha256):
                if verdict.status not in {"malicious", "suspicious"}:
                    continue
                score = 94 if verdict.status == "malicious" else 46
                confidence = 88 if verdict.status == "malicious" else 45
                findings.append(Finding(
                    target=path, engine=f"reputation:{verdict.provider}",
                    threat_type=(
                        "Coincidencia de reputación" if score > 80
                        else "Reputación sospechosa"
                    ),
                    reason=(
                        f"El proveedor {verdict.provider} reporta {verdict.status}; "
                        "revisar contexto."
                    ),
                    severity=severity_from_score(score),
                    risk_score=score, confidence=confidence,
                    evidence_group=f"reputation:{verdict.provider}",
                    sha256=hashes.sha256,
                    details=verdict.details,
                ))
        return findings
