"""Bounded concurrent scan coordinator; does not perform remediation."""
from __future__ import annotations

import logging
import os
import threading
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator
from uuid import uuid4

from app.config import ScanConfig
from core.aggregator import FindingAggregator
from core.detection_engine import DetectionEngine
from core.errors import ScanSkipped
from core.event_bus import EventBus
from core.events import make_event
from core.models import AggregatedFinding, Finding, ScanEvent, ScanStatus, ScanSummary, ScanTarget
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

    def pause(self) -> None:
        """Stop submitting more files; already running tasks may finish."""
        self._resume.clear()
        self.event_bus.publish(ScanEvent("paused"))

    def resume(self) -> None:
        """Allow new tasks to be submitted after a pause."""
        self._resume.set()
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
        for engine in self.engines:
            if self._cancel.is_set():
                break
            try:
                outcome.signals.extend(engine.scan(target))
                outcome.succeeded += 1
            except ScanSkipped as exc:
                outcome.skips.append(f"{engine.name}: {exc}")
                outcome.skip_details.append({
                    "engine": engine.name,
                    "code": exc.code,
                    "params": exc.params,
                })
            except Exception as exc:
                # Engines are independent; a failure in one must not skip others.
                message = f"{engine.name}: {type(exc).__name__}: {exc}"
                outcome.errors.append(message)
                LOG.warning("Error del motor %s: %s", engine.name, type(exc).__name__)
        # Reuse the hash engine's cache for whitelist decisions on YARA-only matches.
        hasher = next((e for e in self.engines if isinstance(e, HashEngine)), None)
        if target.kind == "file" and hasher is not None and outcome.succeeded:
            try:
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
            self.event_bus.publish(ScanEvent("error", {
                "path": str(path),
                "message": f"No fue posible descubrir {path}: {type(exc).__name__}",
            }))

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
                    self.event_bus.publish(ScanEvent("current_target", {
                        "path": str(target.path), "kind": target.kind,
                    }))
                    if len(pending) >= self.config.max_pending:
                        done, pending = wait(pending, return_when=FIRST_COMPLETED)
                        self._process_completed(done, summary)
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
            self.store.finish_session(summary)
            self.last_summary = summary
            self.event_bus.publish(ScanEvent("complete", {
                "session_id": summary.session_id, "status": summary.status.value,
                "discovered": summary.discovered_files, "scanned": summary.scanned_files,
                "finding_files": summary.finding_files, "errors": summary.errors,
                "omitted_checks": summary.omitted_checks,
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
            status = "scanned"
            if outcome.errors or outcome.skips or any(
                item.details.get("limitation") for item in outcome.signals
            ):
                status = "partial" if outcome.succeeded else "error"
            self.store.record_target(
                summary.session_id, outcome.path, status, outcome.sha256,
                "; ".join(outcome.errors + outcome.skips) or None,
            )
            if outcome.kind == "file":
                summary.scanned_files += 1
            else:
                summary.scanned_system_targets += 1
            summary.errors += len(outcome.errors)
            for error in outcome.errors:
                self.event_bus.publish(ScanEvent("error", {
                    "path": str(outcome.path), "message": error,
                }))
            for index, skipped in enumerate(outcome.skips):
                details = (outcome.skip_details[index]
                           if index < len(outcome.skip_details) else {})
                event = make_event(
                    "skipped", str(details.get("code", "SCAN.ENGINE.SKIPPED")),
                    engine=str(details.get("engine", "")),
                    path=str(outcome.path),
                    params=details.get("params"),
                    message=skipped,
                )
                self.store.record_coverage(
                    summary.session_id, outcome.path,
                    str(details.get("engine", "")),
                    str(details.get("code", "SCAN.ENGINE.SKIPPED")),
                    details.get("params") or {}, skipped,
                )
                summary.omitted_checks += 1
                self.event_bus.publish(event)
            allowlist = (
                {outcome.sha256} if outcome.sha256 and self.store.is_whitelisted(outcome.sha256)
                else set()
            )
            # Archive members have independent content hashes, never the ZIP's hash.
            verdicts = []
            for member_target in sorted({signal.target for signal in outcome.signals}):
                member_evidence = [signal for signal in outcome.signals
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
