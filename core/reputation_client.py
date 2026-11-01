"""Opt-in SHA-256-only reputation lookups with cache and request quotas."""
from __future__ import annotations

import logging
import re
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Any

import requests

from app.config import ScanConfig
from db.database import SQLiteStore

LOG = logging.getLogger("oneguard.reputation")
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")


@dataclass(frozen=True, slots=True)
class ReputationVerdict:
    """Provider status: malicious, suspicious, unknown or unavailable."""

    provider: str
    status: str
    details: dict[str, Any]


class SlidingWindowLimiter:
    """Nonblocking process-local window limiter, separate from persistent day quota."""

    def __init__(self, requests_per_minute: int) -> None:
        """Set the maximum number of attempts in any 60-second window."""
        self._limit = requests_per_minute
        self._ticks: deque[float] = deque()
        self._lock = threading.Lock()

    def allow(self) -> bool:
        """Reserve an attempt or refuse without blocking worker threads."""
        with self._lock:
            now = time.monotonic()
            while self._ticks and now - self._ticks[0] >= 60:
                self._ticks.popleft()
            if len(self._ticks) >= self._limit:
                return False
            self._ticks.append(now)
            return True


class ReputationClient:
    """Never uploads files, filenames, command lines or registry values."""

    def __init__(
        self, config: ScanConfig, store: SQLiteStore,
        session: requests.Session | None = None,
    ) -> None:
        """Configure private keys and bounded HTTP clients."""
        self.config = config
        self.store = store
        self.session = session or requests.Session()
        self._limiters = {
            "virustotal": SlidingWindowLimiter(4),
            "malwarebazaar": SlidingWindowLimiter(10),
        }

    def check(self, sha256: str) -> list[ReputationVerdict]:
        """Query selected providers only when the user explicitly consented."""
        if not (self.config.online_enabled and self.config.online_consent):
            return []
        if not _SHA256.fullmatch(sha256):
            raise ValueError("Solo se permite consultar SHA-256 válido")
        verdicts: list[ReputationVerdict] = []
        providers = (
            ("malwarebazaar", self.config.mb_api_key, self._query_malwarebazaar),
            ("virustotal", self.config.vt_api_key, self._query_virustotal),
        )
        for name, api_key, query in providers:
            if not api_key:
                continue
            cached = self.store.get_reputation_cache(
                name, sha256, self.config.reputation_ttl_seconds
            )
            if cached is not None:
                verdicts.append(ReputationVerdict(name, cached["status"], cached["data"]))
                continue
            if not self._limiters[name].allow():
                verdicts.append(ReputationVerdict(
                    name, "unavailable", {"reason": "rate_limited_local"}
                ))
                continue
            # Vendor public API policies differ; VT daily cap is documented 500/day.
            daily_max = 500 if name == "virustotal" else 1000
            if not self.store.reserve_daily_request(name, daily_max):
                verdicts.append(ReputationVerdict(name, "unavailable", {"reason": "daily_quota"}))
                continue
            try:
                verdict = query(sha256, api_key)
            except (requests.RequestException, ValueError, KeyError, TypeError) as exc:
                LOG.warning("Consulta de reputación fallida (%s): %s", name, type(exc).__name__)
                verdicts.append(ReputationVerdict(
                    name, "unavailable", {"reason": type(exc).__name__}
                ))
                continue
            # Do not cache transient provider or authorization errors as clean.
            if verdict.status in {"malicious", "suspicious", "unknown"}:
                self.store.save_reputation_cache(name, sha256, verdict.status, verdict.details)
            verdicts.append(verdict)
        return verdicts

    def _query_malwarebazaar(self, sha256: str, api_key: str) -> ReputationVerdict:
        """POST only hash data to the documented get_info endpoint."""
        response = self.session.post(
            "https://mb-api.abuse.ch/api/v1/",
            headers={"Auth-Key": api_key},
            data={"query": "get_info", "hash": sha256},
            timeout=(5, 12),
        )
        response.raise_for_status()
        result = response.json()
        status = result.get("query_status")
        if status == "ok" and isinstance(result.get("data"), list) and result["data"]:
            sample = result["data"][0]
            return ReputationVerdict("malwarebazaar", "malicious", {
                "family": str(sample.get("signature") or "desconocida")[:128],
                "first_seen": str(sample.get("first_seen") or "")[:64],
            })
        if status == "hash_not_found":
            return ReputationVerdict("malwarebazaar", "unknown", {})
        return ReputationVerdict("malwarebazaar", "unavailable", {"reason": str(status)[:50]})

    def _query_virustotal(self, sha256: str, api_key: str) -> ReputationVerdict:
        """GET an existing file report; never call upload or rescan endpoints."""
        response = self.session.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": api_key},
            timeout=(5, 12),
        )
        if response.status_code == 404:
            return ReputationVerdict("virustotal", "unknown", {})
        response.raise_for_status()
        attributes = response.json()["data"]["attributes"]
        stats = attributes.get("last_analysis_stats") or {}
        malicious = max(0, int(stats.get("malicious", 0)))
        suspicious = max(0, int(stats.get("suspicious", 0)))
        if malicious >= 5:
            status = "malicious"
        elif malicious > 0 or suspicious > 0:
            status = "suspicious"
        else:
            status = "unknown"
        return ReputationVerdict("virustotal", status, {
            "malicious_engines": malicious,
            "suspicious_engines": suspicious,
        })
