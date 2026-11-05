"""Bounded concurrent scan coordinator; does not perform remediation."""
from __future__ import annotations

import logging
import os
import threading
import time
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Callable, Iterator
from uuid import uuid4

from app.config import ScanConfig
from core.aggregator import FindingAggregator
from core.archive_members import ArchiveMemberCoverage
from core.file_identity import (FileIdentity, matches_current_file_identity,
                                observe_file_identity)
from core.system_identity import SystemObservation
from core.detection_engine import DetectionEngine
from core.errors import ScanSkipped
from core.event_bus import EventBus
from core.events import make_event
from core.models import (AggregatedFinding, FileHashes, Finding, ScanEvent,
                         ScanStatus, ScanSummary, ScanTarget)
from core.performance import EngineTiming, PerformanceMonitor
from core.quarantine import quarantine_directory
from db.database import SQLiteStore
from engines.hash_engine import HashEngine

LOG = logging.getLogger("oneguard.scanner")


@dataclass(slots=True)
class TargetOutcome:
    """Analysis result for one file, including partial-engine failures."""

    path: Path
    kind: str = "file"
    signals: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    skips: list[str] = field(default_factory=list)
    skip_details: list[dict] = field(default_factory=list)
    succeeded: int = 0
    sha256: str | None = None
    input_size_bytes: int = 0
    engine_timings: list[EngineTiming] = field(default_factory=list)
    archive_members: list[ArchiveMemberCoverage] = field(default_factory=list)
    system_observation: SystemObservation | None = None
    file_identity: FileIdentity | None = None


def discover_files(
    roots: list[Path], exclusions: tuple[Path, ...] = (),
    on_error: Callable[[Path, OSError], None] | None = None,
) -> Iterator[Path]:
    """Walk local paths without following symlinks or Windows junctions."""
    excluded = tuple(p.absolute() for p in exclusions)

    def is_excluded(path: Path) -> bool:
        """Compare paths component-wise to avoid /temp vs /template confusion."""
        absolute = path.absolute()
        return any(absolute == parent or parent in absolute.parents for parent in excluded)

    pending: list[Path] = list(reversed([Path(p).absolute() for p in roots]))
    visited_dirs: set[tuple[int, int]] = set()
    while pending:
        current = pending.pop()
        if is_excluded(current) or current.is_symlink():
            continue
        try:
            stat = current.stat(follow_symlinks=False)
            if current.is_file():
                yield current
                continue
            if not current.is_dir():
                continue
            # Windows junctions can lead outside selected scope or cycles.
            if hasattr(current, "is_junction") and current.is_junction():
                continue
            identity = (stat.st_dev, stat.st_ino)
            if identity != (0, 0) and identity in visited_dirs:
                continue
            visited_dirs.add(identity)
            with os.scandir(current) as entries:
                for item in entries:
                    pending.append(Path(item.path))
        except (OSError, PermissionError) as exc:
            LOG.warning("No se pudo descubrir %s (%s)", current, type(exc).__name__)
            if on_error is not None:
                on_error(current, exc)


class ScannerManager:
    """Run a bounded worker pool and push immutable events to the UI queue."""

    def __init__(
        self, config: ScanConfig, store: SQLiteStore,
        engines: list[DetectionEngine], event_bus: EventBus | None = None,
    ) -> None:
        """Create controls and verify that at least one engine is installed."""
        if not engines:
            raise ValueError("Se requiere al menos un motor de detección")
        self.config = config
        self.store = store
        self.engines = tuple(engines)
        self.event_bus = event_bus or EventBus()
        self._cancel = threading.Event()
        self._resume = threading.Event()
        self._resume.set()
        self.aggregator = FindingAggregator()
        self.last_summary: ScanSummary | None = None
        self._performance = PerformanceMonitor()
        self._known_targets = 0
        self._discovery_closed = False
        self._last_perf_publish = 0.0
        self._resource_process = None

    def _performance_payload(self, *, allow_estimate: bool = True) -> dict:
        """Prepare local metrics; optional process telemetry cannot break scans."""
        snapshot = self._performance.snapshot(
            known_targets=self._known_targets,
            discovery_complete=self._discovery_closed,
            allow_estimate=allow_estimate,
        )
        try:
            import psutil

            if self._resource_process is None:
                self._resource_process = psutil.Process()
                # First value is not meaningful until the next sample.
                self._resource_process.cpu_percent(interval=None)
            snapshot["process_resources"] = {
                "cpu_percent": round(
                    self._resource_process.cpu_percent(interval=None), 1
                ),
                "rss_bytes": int(self._resource_process.memory_info().rss),
            }
        except Exception:
            # This is optional diagnostic information, not a scan result.
            pass
        return snapshot

    def _emit_performance(self, *, force: bool = False) -> None:
        """Publish bounded metric snapshots, not one event per engine call."""
        now = time.monotonic()
        if not force and now - self._last_perf_publish < 0.8:
            return
        self._last_perf_publish = now
        self.event_bus.publish(ScanEvent(
            "performance", self._performance_payload(
                allow_estimate=not self._cancel.is_set()
            ),
        ))

    def pause(self) -> None:
        """Stop submitting more files; already running tasks may finish."""
        self._resume.clear()
        self._performance.pause()
        self.event_bus.publish(ScanEvent("paused"))

    def resume(self) -> None:
        """Allow new tasks to be submitted after a pause."""
        self._resume.set()
        self._performance.resume()
        self.event_bus.publish(ScanEvent("resumed"))

    def cancel(self) -> None:
        """Request cooperative cancellation and unblock a paused producer."""
        self._cancel.set()
        self._resume.set()
        self.event_bus.publish(ScanEvent("cancelling"))

    def start_async(self, roots: list[Path]) -> threading.Thread:
        """Start the scanner outside the GUI main thread."""
        worker = threading.Thread(target=self.run, args=(roots,), name="oneguard-scan")
        worker.start()
        return worker

    def _scan_target(self, target: ScanTarget) -> TargetOutcome:
        """Collect detections and errors separately without treating errors as clean."""
        outcome = TargetOutcome(path=target.path, kind=target.kind)
        if target.kind == "file":
            try:
                outcome.input_size_bytes = max(0, target.path.stat().st_size)
            except OSError:
                # Engines will record the access failure themselves.
                pass
        # Read the small magic prefix only once for eligibility checks.
        # A failed read is not interpreted as "no malware": actual engines
        # still receive the target and record access errors as appropriate.
        file_header: bytes | None = None
        if target.kind == "file":
            try:
                with target.path.open("rb") as handle:
                    file_header = handle.read(8)
            except OSError:
                pass
        # Record content identity only for plausible PE targets. This separate
        # observation cannot change detection scores or authorize remediation.
        if target.kind == "file" and file_header is not None and (
            file_header.startswith(b"MZ")
            or target.path.suffix.lower() in {".exe", ".dll", ".sys", ".scr"}
        ) and not self._cancel.is_set():
            outcome.file_identity = observe_file_identity(target.path)
            if outcome.file_identity.status != "observed":
                # Report a coverage limit, never a new detection signal.
                description = (
                    "file_identity: "
                    + outcome.file_identity.status + ": "
                    + outcome.file_identity.reason
                )
                outcome.skips.append(description)
                outcome.skip_details.append({
                    "engine": "file_identity",
                    "code": "SCAN.ENGINE.SKIPPED",
                    "params": {"reason": outcome.file_identity.status},
                })
        for idx, engine in enumerate(self.engines):
            if self._cancel.is_set():
                for remaining in self.engines[idx:]:
                    outcome.engine_timings.append(EngineTiming(
                        engine=remaining.name, status="not_run",
                        duration_seconds=0.0, input_size_bytes=0,
                        reason="Análisis cancelado antes de iniciar el motor",
                    ))
                break
            started = time.perf_counter()
            state = "success"
            signal_count = 0
            reason = ""
            try:
                if not engine.applies_to(target, file_header):
                    state = "not_applicable"
                    reason = "El tipo de objetivo no corresponde a este motor"
                    continue
                detailed_scan = getattr(engine, "scan_with_coverage", None)
                observed_scan = getattr(engine, "scan_with_observation", None)
                if callable(detailed_scan):
                    signals, members = detailed_scan(target)
                    outcome.archive_members.extend(members)
                elif callable(observed_scan):
                    signals, observation = observed_scan(target)
                    outcome.system_observation = observation
                    if target.kind == "process" and observation.status != "verified":
                        # Stale/reused/unreadable PIDs are unknown, never clean.
                        state = "skipped"
                        reason = observation.note
                        outcome.skips.append(f"{engine.name}: {reason}")
                        outcome.skip_details.append({
                            "engine": engine.name,
                            "code": "SCAN.ENGINE.SKIPPED",
                            "params": {"reason": observation.status},
                        })
                elif (isinstance(engine, HashEngine) and target.kind == "file"
                      and outcome.file_identity is not None
                      and matches_current_file_identity(target.path, outcome.file_identity)):
                    # One validated bounded read serves both evidence and hash
                    # detection. No persisted cache or hash-only trust shortcut.
                    identity = outcome.file_identity
                    signals = engine.scan_with_hashes(
                        target, FileHashes(identity.sha256, identity.md5, identity.file_size)
                    )
                else:
                    signals = engine.scan(target)
                outcome.signals.extend(signals)
                # Coverage warnings are not detection signals; do not inflate
                # the dashboard's per-engine "Señales" counter.
                signal_count = sum(
                    not finding.details.get("limitation") for finding in signals
                )
                if state == "success":
                    outcome.succeeded += 1
            except ScanSkipped as exc:
                state = "skipped"
                reason = str(exc)
                outcome.skips.append(f"{engine.name}: {exc}")
                outcome.skip_details.append({
                    "engine": engine.name,
                    "code": exc.code,
                    "params": exc.params,
                })
            except Exception as exc:
                # A broken applicability check is an error, never a clean result.
                state = "error"
                reason = f"{type(exc).__name__}: {exc}"
                message = f"{engine.name}: {reason}"
                outcome.errors.append(message)
                LOG.warning("Error del motor %s: %s", engine.name, type(exc).__name__)
            finally:
                outcome.engine_timings.append(EngineTiming(
                    engine=engine.name, status=state,
                    duration_seconds=max(0.0, time.perf_counter() - started),
                    input_size_bytes=(outcome.input_size_bytes
                                      if state not in ("not_applicable", "not_run") else 0),
                    signal_count=signal_count, reason=reason[:500],
                ))
        # A digest observed earlier cannot silently represent a path that
        # changed during subsequent engine work. Preserve this as a coverage
        # omission and let the established hash path re-read current bytes.
        if (outcome.file_identity is not None
                and outcome.file_identity.status == "observed"
                and not matches_current_file_identity(target.path, outcome.file_identity)):
            outcome.file_identity = replace(
                outcome.file_identity, status="changed", sha256="", md5="",
                fingerprint=None,
                reason="Path metadata changed after the content snapshot",
            )
            outcome.skips.append("file_identity: identity changed after observation")
            outcome.skip_details.append({
                "engine": "file_identity",
                "code": "SCAN.ENGINE.SKIPPED",
                "params": {"reason": "changed"},
            })
        # Reuse the hash engine's cache for whitelist decisions on YARA-only matches.
        hasher = next((e for e in self.engines if isinstance(e, HashEngine)), None)
        if target.kind == "file" and hasher is not None and outcome.succeeded:
            try:
                if (outcome.file_identity is not None
                        and matches_current_file_identity(target.path, outcome.file_identity)):
                    outcome.sha256 = outcome.file_identity.sha256
                else:
                    # Metadata changed or bounded identity failed: fall back
                    # to the existing validated hash path for the allowlist.
                    outcome.sha256 = hasher.compute_hashes(target.path).sha256
            except OSError as exc:
                outcome.errors.append(f"hash verification: {type(exc).__name__}")
        return outcome

    def run(
        self, roots: list[Path], extra_targets: list[ScanTarget] | None = None
    ) -> ScanSummary:
        """Analyze selected roots, persist results and return a final summary."""
        # A fresh manager is created per scan. Preserve cancellation requested
        # during preparation instead of silently clearing it on entry.
        if not self._cancel.is_set():
            self._resume.set()
        session_id = uuid4().hex
        summary = ScanSummary(session_id=session_id, status=ScanStatus.RUNNING)
        self._performance = PerformanceMonitor()
        self._known_targets = 0
        self._discovery_closed = False
        self._last_perf_publish = 0.0
        self.store.start_session(session_id)
        self.event_bus.publish(ScanEvent("started", {"session_id": session_id}))
        # Exclude our actively written DB and its WAL/SHM companions.
        db_path = self.config.database_path.absolute()
        exclusions = self.config.exclusions + (
            db_path, Path(str(db_path) + "-wal"), Path(str(db_path) + "-shm"),
            quarantine_directory(),
        )
        pending: set[Future[TargetOutcome]] = set()

        def report_discovery_error(path: Path, exc: OSError) -> None:
            """Count inaccessible paths instead of claiming they were clean."""
            summary.errors += 1
            self.event_bus.publish(make_event(
                "error", "SCAN.DISCOVERY.ERROR", engine="discovery",
                path=str(path), scan_id=summary.session_id,
                message=f"No fue posible descubrir {path}: {type(exc).__name__}",
            ))

        try:
            with ThreadPoolExecutor(max_workers=self.config.max_workers,
                                    thread_name_prefix="oneguard-worker") as executor:
                for path in discover_files(roots, exclusions, on_error=report_discovery_error):
                    if self._cancel.is_set():
                        break
                    # This wait is interruptible via cancel(), which sets _resume.
                    self._resume.wait()
                    if self._cancel.is_set():
                        break
                    target = ScanTarget(path)
                    future = executor.submit(self._scan_target, target)
                    pending.add(future)
                    summary.discovered_files += 1
                    self._known_targets += 1
                    self.event_bus.publish(ScanEvent("current_target", {"path": str(path)}))
                    if len(pending) >= self.config.max_pending:
                        done, pending = wait(pending, return_when=FIRST_COMPLETED)
                        self._process_completed(done, summary)
                for target in (extra_targets or []):
                    if self._cancel.is_set():
                        break
                    self._resume.wait()
                    if self._cancel.is_set():
                        break
                    pending.add(executor.submit(self._scan_target, target))
                    self._known_targets += 1
                    self.event_bus.publish(ScanEvent("current_target", {
                        "path": str(target.path), "kind": target.kind,
                    }))
                    if len(pending) >= self.config.max_pending:
                        done, pending = wait(pending, return_when=FIRST_COMPLETED)
                        self._process_completed(done, summary)
                self._discovery_closed = True
                self._emit_performance(force=True)
                # Only already-started tasks are allowed to complete after cancel.
                if self._cancel.is_set():
                    for job in pending:
                        job.cancel()
                while pending:
                    done, pending = wait(pending, return_when=FIRST_COMPLETED)
                    self._process_completed(done, summary)
            summary.status = ScanStatus.CANCELLED if self._cancel.is_set() else ScanStatus.COMPLETED
        except Exception as exc:
            LOG.exception("Error no recuperable de coordinación: %s", type(exc).__name__)
            summary.errors += 1
            summary.status = ScanStatus.FAILED
            self.event_bus.publish(ScanEvent("error", {"message": str(exc)}))
        finally:
            self._performance.finish()
            summary.engine_metrics = self._performance.engine_metrics()
            self.store.save_engine_metrics(summary.session_id, summary.engine_metrics)
            self.store.finish_session(summary)
            self.last_summary = summary
            self.event_bus.publish(ScanEvent("complete", {
                "session_id": summary.session_id, "status": summary.status.value,
                "discovered": summary.discovered_files, "scanned": summary.scanned_files,
                "finding_files": summary.finding_files, "errors": summary.errors,
                "omitted_checks": summary.omitted_checks,
                "performance": self._performance_payload(
                    allow_estimate=False
                ),
            }))
        return summary

    def _process_completed(
        self, completed: set[Future[TargetOutcome]], summary: ScanSummary
    ) -> None:
        """Persist a batch and publish results to the presentation layer."""
        for future in completed:
            if future.cancelled():
                continue
            try:
                outcome = future.result()
            except Exception as exc:
                summary.errors += 1
                self.event_bus.publish(ScanEvent("error", {"message": str(exc)}))
                continue
            self._performance.record_target(
                input_size_bytes=outcome.input_size_bytes,
                timings=outcome.engine_timings,
            )
            status = "scanned"
            if outcome.errors:
                status = "partial" if outcome.succeeded else "error"
            elif outcome.skips or any(
                item.details.get("limitation") for item in outcome.signals
            ) or any(
                member.status != "inspected" for member in outcome.archive_members
            ):
                # A known coverage omission is not an unexpected engine error,
                # even if no other engine was applicable to the target.
                status = "partial"
            if not outcome.succeeded and all(
                item.status in ("not_applicable", "not_run")
                for item in outcome.engine_timings
            ):
                status = "not_applicable" if not self._cancel.is_set() else "partial"
            self.store.record_target_engine_runs(
                summary.session_id, outcome.path, status,
                outcome.engine_timings, outcome.sha256,
                "; ".join(outcome.errors + outcome.skips) or None,
                archive_members=outcome.archive_members,
                system_observation=outcome.system_observation,
                file_identity=outcome.file_identity,
            )
            # Archive members may be unavailable even when the ArchiveEngine
            # itself returned normally. Emit one grouped coverage notice per
            # container rather than one misleading "malware finding" per member.
            limited_members = [
                row for row in outcome.archive_members
                if row.status != "inspected"
            ]
            if limited_members:
                affected = [
                    row for row in limited_members
                    if row.member_path != str(outcome.path)
                ] or limited_members
                counts = {
                    "uninspected_members": sum(
                        row.status == "uninspected" for row in affected
                    ),
                    "partial_members": sum(
                        row.status == "partial" for row in affected
                    ),
                }
                notice = make_event(
                    "skipped", "SCAN.ARCHIVE.PARTIAL", engine="archive",
                    path=str(outcome.path), scan_id=summary.session_id,
                    params=counts,
                    message=(
                        "Archivo comprimido con cobertura parcial: "
                        f"{counts['uninspected_members']} no inspeccionados, "
                        f"{counts['partial_members']} parciales"
                    ),
                )
                self.store.record_coverage(
                    summary.session_id, outcome.path, "archive",
                    "SCAN.ARCHIVE.PARTIAL", counts,
                    notice.payload["message"],
                )
                summary.omitted_checks += 1
                self.event_bus.publish(notice)
            if outcome.kind == "file":
                summary.scanned_files += 1
            else:
                summary.scanned_system_targets += 1
            summary.errors += len(outcome.errors)
            for error in outcome.errors:
                self.event_bus.publish(make_event(
                    "error", "SCAN.ENGINE.ERROR",
                    engine=error.split(":", 1)[0],
                    path=str(outcome.path), scan_id=summary.session_id,
                    message=error,
                ))
            for index, skipped in enumerate(outcome.skips):
                details = (outcome.skip_details[index]
                           if index < len(outcome.skip_details) else {})
                try:
                    event = make_event(
                        "skipped", str(details.get("code", "SCAN.ENGINE.SKIPPED")),
                        engine=str(details.get("engine", "")),
                        path=str(outcome.path),
                        params=details.get("params"),
                        message=skipped, scan_id=summary.session_id,
                    )
                except ValueError:
                    # Invalid third-party engine codes do not abort the scan.
                    event = make_event(
                        "skipped", "SCAN.ENGINE.SKIPPED",
                        engine=str(details.get("engine", "")),
                        path=str(outcome.path), message=skipped,
                        scan_id=summary.session_id,
                    )
                self.store.record_coverage(
                    summary.session_id, outcome.path,
                    str(details.get("engine", "")),
                    event.payload["event_code"],
                    event.payload["message_params"], skipped,
                )
                summary.omitted_checks += 1
                self.event_bus.publish(event)
            allowlist = (
                {outcome.sha256} if outcome.sha256 and self.store.is_whitelisted(outcome.sha256)
                else set()
            )
            # Archive members have independent content hashes, never the ZIP's hash.
            # Resource/cipher/decoder limitations describe coverage, not
            # malware. ArchiveEngine keeps these as informational Finding
            # objects for its legacy API, but they must never inflate threats.
            verdict_signals = [
                signal for signal in outcome.signals
                if not signal.details.get("limitation")
            ]
            verdicts = []
            for member_target in sorted({signal.target for signal in verdict_signals}):
                member_evidence = [signal for signal in verdict_signals
                                   if signal.target == member_target]
                member_hash = next((s.sha256 for s in member_evidence if s.sha256), None)
                member_allowlist = (
                    {member_hash} if member_hash and self.store.is_whitelisted(member_hash)
                    else set()
                )
                verdicts.extend(self.aggregator.aggregate(
                    member_evidence,
                    whitelisted_hashes=allowlist if member_target == str(outcome.path)
                    else member_allowlist,
                    target_sha256=outcome.sha256 if member_target == str(outcome.path) else None,
                ))
            if verdicts:
                summary.finding_files += 1
            for verdict in verdicts:
                self.store.save_finding(summary.session_id, verdict)
                summary.findings.append(verdict)
                self.event_bus.publish(ScanEvent("finding", {
                    "target": verdict.target, "severity": verdict.severity.value,
                    "score": verdict.risk_score, "confidence": verdict.confidence,
                    "type": verdict.threat_type, "suppressed": verdict.suppressed,
                }))
            self.event_bus.publish(ScanEvent("progress", {
                "discovered": summary.discovered_files,
                "scanned": summary.scanned_files,
                "system_scanned": summary.scanned_system_targets,
                "errors": summary.errors,
            }))
        self._emit_performance()
