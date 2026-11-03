"""Qt-independent controller for read-only scan operations and event delivery."""
from __future__ import annotations

import sys
import threading
from dataclasses import replace
from pathlib import Path

from app.config import ScanConfig
from core.errors import RuleLoadError
from core.event_bus import EventBus
from core.events import make_event
from core.models import ScanEvent, ScanTarget
from core.investigation import IncidentInvestigator
from core.reputation_client import ReputationClient
from core.scanner_manager import ScannerManager
from db.database import SQLiteStore
from engines.archive_engine import ArchiveEngine
from engines.hash_engine import HashEngine
from engines.pe_engine import PEEngine
from engines.persistence_engine import PersistenceEngine
from engines.process_engine import ProcessEngine
from engines.script_engine import ScriptEngine
from engines.yara_engine import YaraEngine
from ui.profiles import ScanPlan


class ScanController:
    """Manage one background scan while exposing a queue to the GUI main thread."""

    def __init__(self, base_config: ScanConfig, event_bus: EventBus | None = None) -> None:
        self.base_config = base_config
        self.bus = event_bus or EventBus()
        self._thread: threading.Thread | None = None
        self._manager: ScannerManager | None = None
        self._cancel_requested = threading.Event()

    @property
    def running(self) -> bool:
        """Whether scan setup or the worker is still active."""
        return self._thread is not None and self._thread.is_alive()

    def start(self, plan: ScanPlan, *, vt_key: str = "", mb_key: str = "") -> None:
        """Launch engine setup, enumeration and scanning outside the GUI thread."""
        if self.running:
            raise RuntimeError("Ya hay un análisis en ejecución")
        self._cancel_requested.clear()
        self.bus = EventBus()
        self._manager = None
        self._thread = threading.Thread(
            target=self._work, args=(plan, vt_key, mb_key),
            name="oneguard-gui-worker", daemon=False,
        )
        self._thread.start()

    def _work(self, plan: ScanPlan, vt_key: str, mb_key: str) -> None:
        """Prepare engines and run the same core as the existing CLI."""
        try:
            self.bus.publish(ScanEvent("phase", {"name": "Preparando motores de detección"}))
            config = replace(
                self.base_config, online_consent=plan.online,
                online_enabled=plan.online, vt_api_key=vt_key, mb_api_key=mb_key,
            )
            store = SQLiteStore(config.database_path)
            reputation = ReputationClient(config, store) if plan.online and (vt_key or mb_key) else None
            if plan.online and reputation is None:
                self.bus.publish(make_event(
                    "warning", "SCAN.REPUTATION.UNCONFIGURED", engine="reputation",
                ))
            hash_engine = HashEngine(store, reputation)
            engines = [hash_engine]
            yara_engine = None
            try:
                yara_engine = YaraEngine(
                    config.rule_directory, max_file_size=config.yara_max_file_size,
                    timeout_seconds=config.yara_timeout_seconds,
                )
                engines.append(yara_engine)
            except RuleLoadError as exc:
                self.bus.publish(make_event(
                    "warning", "SCAN.YARA.UNAVAILABLE", engine="yara",
                    message=f"{type(exc).__name__}: {exc}",
                ))
            pe_engine = PEEngine(max_file_size=config.pe_max_file_size)
            script_engine = ScriptEngine(max_script_bytes=config.script_max_bytes)
            engines.extend((pe_engine, script_engine))
            engines.append(ArchiveEngine(
                store, yara_engine=yara_engine, script_engine=script_engine,
                pe_engine=pe_engine, max_depth=config.archive_max_depth,
                max_entries=config.archive_max_entries,
                max_total_bytes=config.archive_max_total_bytes,
                max_member_bytes=config.archive_max_member_bytes,
                max_seconds=config.archive_timeout_seconds,
            ))
            extra_targets: list[ScanTarget] = []
            if plan.processes or plan.persistence:
                if sys.platform != "win32":
                    self.bus.publish(ScanEvent("warning", {
                        "message": "Inventario de Windows no disponible en este sistema.",
                    }))
                else:
                    self.bus.publish(ScanEvent("phase", {"name": "Inventariando componentes Windows"}))
                    if plan.processes:
                        process_engine = ProcessEngine()
                        engines.append(process_engine)
                        try:
                            process_targets = process_engine.enumerate_targets()
                            extra_targets.extend(process_targets)
                            if not process_targets:
                                self.bus.publish(ScanEvent("warning", {
                                    "message": "No se obtuvo inventario de procesos; cobertura no verificada.",
                                }))
                        except Exception as exc:
                            self.bus.publish(ScanEvent("warning", {
                                "message": f"Procesos: inventario parcial ({type(exc).__name__})",
                            }))
                    if plan.persistence:
                        persistence_engine = PersistenceEngine()
                        engines.append(persistence_engine)
                        try:
                            persistence_targets = persistence_engine.enumerate_targets()
                            extra_targets.extend(persistence_targets)
                            if not persistence_targets:
                                self.bus.publish(ScanEvent("warning", {
                                    "message": "No se obtuvo inventario de persistencia; cobertura no verificada.",
                                }))
                        except Exception as exc:
                            self.bus.publish(ScanEvent("warning", {
                                "message": f"Persistencia: inventario parcial ({type(exc).__name__})",
                            }))
            if self._cancel_requested.is_set():
                self.bus.publish(ScanEvent("complete", {
                    "status": "cancelled", "scanned": 0, "discovered": 0,
                    "finding_files": 0, "errors": 0,
                }))
                return
            self.bus.publish(ScanEvent("phase", {"name": "Analizando archivos y objetos del sistema"}))
            self._manager = ScannerManager(config, store, engines, self.bus)
            summary = self._manager.run(list(plan.roots), extra_targets)
            try:
                report = IncidentInvestigator().investigate(summary.findings)
                self.bus.publish(ScanEvent("investigation", report.as_dict()))
            except Exception as exc:
                self.bus.publish(ScanEvent("warning", {
                    "message": f"Investigación no disponible: {type(exc).__name__}",
                }))
        except Exception as exc:
            self.bus.publish(ScanEvent("error", {
                "message": f"Error al iniciar: {type(exc).__name__}: {exc}",
            }))
            self.bus.publish(ScanEvent("complete", {
                "status": "failed", "scanned": 0, "discovered": 0,
                "finding_files": 0, "errors": 1,
            }))

    def pause(self) -> None:
        """Request cooperative pause; in-flight file operations may still finish."""
        if self.running and self._manager:
            self._manager.pause()

    def resume(self) -> None:
        """Continue task submissions after a pause."""
        if self.running and self._manager:
            self._manager.resume()

    def cancel(self) -> None:
        """Cancel setup or stop future work without terminating scanner threads."""
        self._cancel_requested.set()
        if self._manager:
            self._manager.cancel()

    @property
    def last_summary(self):
        """Return most recent core summary if it exists."""
        return self._manager.last_summary if self._manager else None
