"""Sentinel OneGuard CLI: inspect, register test signatures and export offline reports."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from queue import Empty

from app.config import ScanConfig, load_config_file
from core.event_bus import EventBus
from core.logging_setup import configure_logging
from core.scanner_manager import ScannerManager
from db.database import SQLiteStore
from engines.hash_engine import HashEngine
from engines.yara_engine import YaraEngine
from core.errors import RuleLoadError
from core.reputation_client import ReputationClient
from core.investigation import IncidentInvestigator
from core.report import ReportService
from engines.pe_engine import PEEngine
from engines.script_engine import ScriptEngine
from engines.archive_engine import ArchiveEngine
from engines.process_engine import ProcessEngine
from engines.persistence_engine import PersistenceEngine


def build_parser() -> argparse.ArgumentParser:
    """Describe safe, opt-in Phase 3 operations."""
    parser = argparse.ArgumentParser(description="Sentinel OneGuard — análisis, investigación y respuesta experimental")
    parser.add_argument(
        "--database", type=Path, help="Ruta de SQLite (por defecto, datos de usuario)"
    )
    parser.add_argument("--config", type=Path, help="Configuración TOML opcional")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="Analizar uno o varios archivos o directorios")
    scan.add_argument("paths", nargs="*", type=Path)
    scan.add_argument("--no-yara", action="store_true")
    scan.add_argument("--no-pe", action="store_true", help="No inspeccionar ejecutables PE")
    scan.add_argument("--no-archives", action="store_true", help="No inspeccionar comprimidos")
    scan.add_argument("--no-scripts", action="store_true", help="No analizar scripts y documentos Office")
    scan.add_argument("--system", action="store_true", help="Consentimiento CLI para leer procesos y persistencia en Windows")
    scan.add_argument("--investigate", action="store_true", help="Mostrar asociaciones de hallazgos, sin afirmar causalidad")
    scan.add_argument("--rules", type=Path)
    scan.add_argument("--workers", type=int, default=None)
    scan.add_argument("--exclude", action="append", type=Path, default=[])
    scan.add_argument(
        "--online", action="store_true",
        help="Consentimiento explícito: consultar solo hashes",
    )
    scan.add_argument("--verbose", action="store_true")
    report = commands.add_parser("report", help="Exportar un análisis anterior como HTML/CSV")
    report.add_argument("--session", required=True, help="ID de la sesión guardada")
    report.add_argument("--format", choices=("html", "csv"), required=True)
    report.add_argument("--output", type=Path, required=True,
                        help="Archivo nuevo; no se sobrescriben archivos existentes")
    signatures = commands.add_parser(
        "add-signature", help="Añadir un SHA-256 revisado a las firmas locales"
    )
    signatures.add_argument("sha256")
    signatures.add_argument("--name", required=True)
    signatures.add_argument("--type", required=True)
    signatures.add_argument("--reason", required=True)
    signatures.add_argument("--score", type=int, default=95)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Initialize the database and run an explicitly authorized analysis."""
    configure_logging()
    args = build_parser().parse_args(argv)
    try:
        default_config = load_config_file(args.config) if args.config else ScanConfig()
    except (OSError, ValueError) as exc:
        print(f"Error de configuración: {exc}", file=sys.stderr)
        return 2
    db_path = args.database or default_config.database_path
    store = SQLiteStore(db_path)
    if args.command == "report":
        try:
            service = ReportService(store)
            result = (service.export_html(args.session, args.output)
                      if args.format == "html" else service.export_csv(args.session, args.output))
        except (OSError, ValueError) as exc:
            print(f"No se pudo exportar: {exc}", file=sys.stderr)
            return 2
        print(f"Informe local guardado: {result}")
        return 0
    if args.command == "add-signature":
        store.add_hash_signature(args.sha256, args.name, args.type,
                                 args.reason, risk_score=args.score)
        print("Firma SHA-256 registrada; no se realizó ningún análisis.")
        return 0
    config = ScanConfig(
        database_path=db_path,
        rule_directory=args.rules or default_config.rule_directory,
        exclusions=default_config.exclusions + tuple(args.exclude),
        max_workers=args.workers or default_config.max_workers,
        max_pending=max(
            default_config.max_pending,
            (args.workers or default_config.max_workers) * 4,
        ),
        yara_max_file_size=default_config.yara_max_file_size,
        yara_timeout_seconds=default_config.yara_timeout_seconds,
        online_consent=args.online, online_enabled=args.online,
        pe_max_file_size=default_config.pe_max_file_size,
        script_max_bytes=default_config.script_max_bytes,
        archive_max_depth=default_config.archive_max_depth,
        archive_max_entries=default_config.archive_max_entries,
        archive_max_total_bytes=default_config.archive_max_total_bytes,
        archive_max_member_bytes=default_config.archive_max_member_bytes,
        archive_timeout_seconds=default_config.archive_timeout_seconds,
    )
    if args.online and not (config.mb_api_key or config.vt_api_key):
        print(
            "Aviso: sin ONEGUARD_MB_API_KEY/ONEGUARD_VT_API_KEY; análisis solo local.",
            file=sys.stderr,
        )
    reputation = ReputationClient(config, store) if args.online else None
    engines = [HashEngine(store, reputation)]
    yara_engine = None
    if not args.no_yara:
        try:
            yara_engine = YaraEngine(config.rule_directory,
                                      max_file_size=config.yara_max_file_size,
                                      timeout_seconds=config.yara_timeout_seconds)
            engines.append(yara_engine)
        except RuleLoadError as exc:
            print(f"YARA no disponible: {exc}", file=sys.stderr)
            return 2
    script_engine = ScriptEngine(max_script_bytes=config.script_max_bytes)
    if not args.no_pe:
        engines.append(PEEngine(max_file_size=config.pe_max_file_size))
    if not args.no_scripts:
        engines.append(script_engine)
    if not args.no_archives:
        engines.append(ArchiveEngine(
            store, yara_engine=yara_engine, script_engine=script_engine,
            pe_engine=PEEngine(max_file_size=config.pe_max_file_size),
            max_depth=config.archive_max_depth, max_entries=config.archive_max_entries,
            max_total_bytes=config.archive_max_total_bytes,
            max_member_bytes=config.archive_max_member_bytes,
            max_seconds=config.archive_timeout_seconds,
        ))
    system_targets = []
    if args.system:
        if sys.platform != "win32":
            print("--system requiere Windows 10/11; no se simuló un inventario.", file=sys.stderr)
            return 2
        process_engine = ProcessEngine()
        persistence_engine = PersistenceEngine()
        engines.extend([process_engine, persistence_engine])
        try:
            system_targets.extend(process_engine.enumerate_targets())
            system_targets.extend(persistence_engine.enumerate_targets())
        except Exception as exc:
            print(f"Inventario del sistema falló: {type(exc).__name__}", file=sys.stderr)
            return 2
        if not system_targets:
            print("Advertencia: --system no obtuvo objetivos; no equivale a un sistema limpio.",
                  file=sys.stderr)
            if not args.paths:
                return 2
    if not args.paths and not args.system:
        print("Selecciona rutas o utiliza --system para inventario Windows.", file=sys.stderr)
        return 2
    print(
        "ADVERTENCIA: prototipo forense de laboratorio, sin cobertura completa; "
        "cero hallazgos NO significa que el equipo esté limpio.",
        file=sys.stderr,
    )
    bus = EventBus()
    manager = ScannerManager(config, store, engines, bus)
    missing = [str(path) for path in args.paths if not path.exists()]
    if missing:
        print(f"Rutas no encontradas: {', '.join(missing)}", file=sys.stderr)
        return 2
    thread = manager.start_async(args.paths) if not system_targets else None
    if system_targets:
        import threading
        thread = threading.Thread(target=manager.run,
                                  args=(args.paths, system_targets), name="oneguard-system-scan")
        thread.start()
    assert thread is not None
    try:
        while thread.is_alive() or not bus.queue.empty():
            try:
                event = bus.queue.get(timeout=0.15)
            except Empty:
                continue
            if event.kind == "finding":
                print(f"[{event.payload['severity'].upper()}] {event.payload['type']}: "
                      f"{event.payload['target']} (riesgo {event.payload['score']}/100)")
            elif event.kind == "error":
                print(f"[ERROR] {event.payload.get('message', '')}", file=sys.stderr)
            elif event.kind == "skipped" and args.verbose:
                print(f"[PARCIAL] {event.payload['message']}", file=sys.stderr)
            elif event.kind == "progress" and args.verbose:
                print(f"[PROGRESO] {event.payload['scanned']}/{event.payload['discovered']}")
    except KeyboardInterrupt:
        print("Cancelación solicitada; terminando operaciones en curso...", file=sys.stderr)
        manager.cancel()
    thread.join()
    summary = manager.last_summary
    if summary is None:
        print("Error interno: no se recibió resumen", file=sys.stderr)
        return 2
    if args.investigate:
        print(json.dumps({"investigation": IncidentInvestigator().investigate(
            summary.findings).as_dict()}, ensure_ascii=False, indent=2))
    print(json.dumps({
        "session_id": summary.session_id,
        "status": summary.status.value,
        "discovered": summary.discovered_files,
        "scanned": summary.scanned_files,
        "system_scanned": summary.scanned_system_targets,
        "findings": summary.finding_files,
        "errors": summary.errors,
        "database": str(db_path),
    }, ensure_ascii=False, indent=2))
    return 0 if summary.status.value == "completed" else 1


if __name__ == "__main__":
    sys.exit(main())
