# GUI Fase 4 — contrato de diseño y límites de seguridad

## Flujo

```text
QApplication (main Qt thread)
  ├─ OneGuardWindow / ConsentWizard
  │    └─ build_plan() [pure validation; no file read]
  ├─ QTimer every 90ms [drains <=250 core events]
  │    ├─ Console / metrics / phase and discovered work
  │    ├─ Results model and filter
  │    └─ Investigation summary
  └─ ScanController.start() [returns promptly]
       └─ Python worker thread
           ├─ Initialize SQLite, engines (YARA compile), optional reputation
           ├─ Enumerate consented Windows targets
           ├─ ScannerManager.run() [pool, queue, SQLite]
           │    ├─ EventBus -> 'started','phase','progress','finding',...
           │    └─ 'complete' (may be cancelled/failed)
           └─ IncidentInvestigator.investigate(summary.findings)
                └─ 'investigation' (associations, not causality)
```

The UI does not call `scan()` directly. Database read queries are bounded, timeout is short, and EventBus has bounded size. Results can be updated during scanning; completion reconciles with persisted data. The old CLI remains available via `main.py`.

## Permission properties

1. No scan begins from initial app launch. Wizard is required.
2. `read_files` is mandatory; process/persistence/online are independent choices.
3. Online queries are disabled until selected and only send SHA-256; keys are ephemeral.
4. Existing config exclusions are passed to the unchanged manager. Runtime full disk scope is fixed disks only, not network.
5. Lack of permissions or a native dependency triggers a warning or partial result, never a clean verdict.
6. No remediation code is invoked anywhere in the UI. The disabled button explicitly says Fase 5.
7. Historical views are read-only. No browsing history, secrets, or raw network endpoints are uploaded.

## Responsiveness tradeoffs

- The original file discovery is streaming. Therefore no reliable total count exists before finishing discovery: global progress is indeterminate, and phase progress is only known work.
- Pause stops new submissions but not an in-flight file read. Cancellation is cooperative.
- Qt main thread only handles events; high-latency YARA compile/process inventory runs in worker thread.
- Native parsers/compressors in Fase 3 are not yet isolated into sub-processes: thread-based cancellation cannot guarantee a hard timeout of a wedged C extension. This is a security/robustness limitation, not a promise.
- Model displays at most 2500 findings; full history pagination/search is a future enhancement.

## Windows 10/11 manual acceptance checklist

1. Fresh Windows VM snapshot, Python 3.11 x64, PySide6 wheels installed.
2. `python run_gui.py`: title, sidebar, navigation and no scan before permission.
3. Wizard: without file consent continue disabled; opt-in online off by default; custom paths required.
4. Custom scan of inert fixture: data from SQLite appears in live log and results, with a true record ID and evidence.
5. While scanning >1000 test files, move and resize window, switch tabs, pause/resume/cancel; Qt event loop remains responsive.
6. History persists after app restart and double click restores real findings.
7. Without YARA binding: warning appears and scan continues with other engines.
8. No online consent: verify (with network monitoring) zero external reputation requests.
9. Without privileges: inaccessible files/Windows objects never show as confirmed clean.
10. All mitigation actions visibly disabled; no file/registry/process modifications.

This checklist **has not been fully executed** in the Linux packaging environment.
