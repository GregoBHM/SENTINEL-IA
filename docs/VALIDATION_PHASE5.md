# Registro de validación — Fase 5

Entorno de trabajo: Linux (Python 3.13). No se simuló una máquina Windows real ni se ejecutó malware.

- `python -m pytest -q --disable-warnings`: **84 passed, 4 skipped**.
- `python -m compileall -q .`: sin errores de sintaxis.
- Integración CLI: registró SHA-256 de un archivo inocuo en SQLite, lo analizó sin motores opcionales, generó 1 hallazgo sintético y exportó informes HTML y CSV correctamente.
- Cuarentena/restauración con fichero sintético en directorios de prueba, no del sistema.
- Simulaciones de registro Win32 en memoria: desactivación/restauración HKCU, bloqueo de dato modificado y de HKLM.
- Simulación de proceso crítico: se negó terminar `lsass.exe`.
- Pendiente: 3 casos YARA nativos y 1 smoke GUI PySide6 no ejecutables en este Linux.

**Sin validar todavía en Windows:** permisos y herencia ACL, icacls, UAC, bloqueo de archivos por Defender, límites de volumen NTFS, race conditions, operaciones de respuesta del GUI, reparación del registro, y ejecutable PyInstaller. En consecuencia, esta versión no está autorizada para desinfectar sistemas productivos.
