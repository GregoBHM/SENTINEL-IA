# Sentinel OneGuard — Escáner antimalware experimental para Windows

### Descarga Windows · v0.6.0-beta.2

[**Descargar SentinelOneGuard.exe (Windows 10/11 x64)**](https://github.com/GregoBHM/SENTINEL-IA/releases/download/v0.6.0-beta.2/SentinelOneGuard.exe)
&nbsp; · &nbsp; [Ver la versión en Releases](https://github.com/GregoBHM/SENTINEL-IA/releases/tag/v0.6.0-beta.2)
&nbsp; · &nbsp; [SHA-256](https://github.com/GregoBHM/SENTINEL-IA/releases/download/v0.6.0-beta.2/SentinelOneGuard.sha256.txt)

> **PRE-RELEASE EXPERIMENTAL — No es un antivirus de producción.** Ejecuta primero en una VM con snapshot. La mitigación no está validada para recuperar equipos comprometidos y no sustituye Microsoft Defender.

> **ESTADO: PROTOTIPO. No está listo para desinfectar un equipo comprometido de verdad.** No hay protección en tiempo real, no sustituye Microsoft Defender, existen falsos positivos y negativos, el análisis puede ser parcial y no permite declarar Windows limpio.

**Objetivo:** detectar, explicar, investigar y ofrecer mitigaciones aprobadas, para ayudar a determinar si un equipo puede recuperarse sin formatear. Robo de cuentas es solamente uno entre muchos escenarios.

## Entrega

**Descarga Windows (experimental):** [Releases](https://github.com/GregoBHM/SENTINEL-IA/releases). Para publicar una nueva versión, actualiza `RELEASE_VERSION.txt` a un tag nuevo (por ejemplo `v0.6.0-beta.2`) y haz push a `main`. El workflow compila, valida y publica la pre-release si todo es correcto. [Instrucciones detalladas](docs/BUILD_WINDOWS.md).

Consulta `RELEASE_NOTES.md` para el contenido de esta versión y las verificaciones pendientes.

Se conservan los motores y la GUI de Fases 1–4, el escudo PNG/ICO y la compilación Windows. Los binarios de prueba se publican en [GitHub Releases](https://github.com/GregoBHM/SENTINEL-IA/releases) como **pre-releases experimentales**, con etiqueta de versión, `SentinelOneGuard.exe` y SHA-256. También puedes generarlos localmente o con Actions. **Compilar y verificar el EXE no certifica la detección ni la mitigación en equipos comprometidos.**

### Nuevos módulos

| Módulo | Función |
|---|---|
| `core/remediation_policy.py` | Confirmación literal, validación de rutas y hashes, rechazo de enlaces, ubicaciones protegidas y hardlinks. |
| `core/quarantine.py` | Cuarentena bajo estado SQLite, permisos restrictivos, restauración y borrado de blobs; no modifica archivos sin confirmación. |
| `core/process_response.py` | Finalización controlada de proceso solo en Windows y solo tras comprobar instancia. |
| `core/persistence_response.py` | Desactivar/restaurar `HKCU Run/RunOnce` con backup, nunca HKLM ni servicios. |
| `core/report.py` | Exportar sesiones a HTML o CSV offline, con escapes anti-XSS y contra fórmulas. |
| `core/recovery_guidance.py` | Guía contextual según hallazgo y cobertura. |
| `ui/window.py` | Controles de respuesta, pestaña Cuarentena, registro de autoruns e informes; trabajo en hilo aparte y confirmaciones en UI. |
| `tests/phase5/` | Pruebas con archivos y entradas sintéticos, nunca malware real. |

## Ejecución en Windows 10/11 (primero en una VM con snapshot)

Instala Python 3.11+ x64, abre PowerShell en la carpeta del proyecto:

```powershell
py -3.11 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements-gui.txt -r requirements-dev.txt
.venv\Scripts\python.exe -m pytest -q
.venv\Scripts\python.exe run_gui.py
```

Para generar un archivo sintético de prueba:

```powershell
.venv\Scripts\python.exe tools\create_synthetic_test.py
.venv\Scripts\python.exe tools\show_sha256.py synthetic_fixture.txt
.venv\Scripts\python.exe main.py add-signature PEGAR_SHA256 --name "Fixture inocuo" --type "Synthetic" --reason "Prueba local"
```

En la interfaz selecciona **Análisis personalizado** sobre `synthetic_fixture.txt` y confirma lectura. No subas material privado a ninguna API. Las consultas por hash están desactivadas por defecto.

### Reportes por CLI (sin PySide6)

```powershell
.venv\Scripts\python.exe main.py report --session SESSION_ID --format html --output informe.html
.venv\Scripts\python.exe main.py report --session SESSION_ID --format csv --output informe.csv
```

`SESSION_ID` procede del historial o SQLite. El archivo de salida debe ser nuevo. Los informes pueden contener rutas privadas, por lo que debes almacenarlos de forma segura.

### Mitigación desde la GUI

Selecciona un hallazgo; dependiendo de la evidencia podrás solicitar: **Cuarentena**, **Ignorar por SHA-256**, **Finalizar proceso** y **Desactivar HKCU Run**. La interfaz solicitará aprobación y la frase exacta. La pestaña **Cuarentena** muestra estados, permite restaurar y eliminar objetos aislados y recuperar una entrada HKCU autorizada. La exportación HTML/CSV está disponible en **Hallazgos**. Las opciones que no cumplen la política de seguridad se rechazan; no se intenta forzar la operación.

**No hay limpieza automática.** Una cuarentena de archivo no restaura cookies robadas, revoca sesiones, deshace cifrado, desinstala rootkits ni demuestra la causa original. Tras una mitigación, realiza otro análisis y valora las limitaciones de cobertura. Ver `docs/PHASE5_RECOVERY.md`.

## Verificaciones realizadas

- 84 pruebas aprobadas y 4 omitidas en Linux.
- Verificados: estados de cuarentena en POSIX, aprobación explícita, SHA-256, restauración sin sobrescribir, eliminación solo en vault, rechazado de symlinks/hardlinks, auditoría, exportación HTML/CSV, mitigación no disponible fuera de Windows y regresiones de fases previas.
- Las cuatro omitidas corresponden a integraciones nativas ausentes en este entorno (YARA y PySide6), no a pruebas que hayan pasado.
- `compileall` de todo el código ejecutado con éxito.
- **NO verificado:** PySide6 renderizado en Windows, Win32 ACL/UAC y reparación del registro, finalización de procesos Windows, ejecución del `.exe`, aislamiento de archivos comprimidos, certificación antimalware.

El instalador/EXE preparado anteriormente conserva su logo, `.ico`, `build.spec` y script reproducible para Windows. No está firmado digitalmente.

## Limitaciones y seguridad

- La cuarentena está limitada a archivos regulares locales con SHA-256 registrado, no objetos dentro de ZIP ni archivos de sistema. En volúmenes distintos falla explícitamente.
- La escritura en `%ProgramData%` y permisos con `icacls` requieren elevación y validación en VM. Si ACL no se puede aplicar, la operación falla y puede quedar marcada como `needs_review`; nunca se declara reparado.
- En Windows, restaurar restablece permisos heredados con `icacls /reset`; esto **no garantiza preservar exactamente ACL originales**. No se sobrescriben archivos.
- La mitigación elevada basada en rutas puede estar expuesta a cambios concurrentes de un usuario o malware (TOCTOU). Debe endurecerse con operaciones por *handles* Win32 y procesos de privilegios mínimos antes de uso real.
- Las reglas incluidas son **sintéticas** y la base de firmas real no está incluida. No existe medición representativa de precisión y falsos positivos.
- Un hash o un indicador heurístico no prueba exfiltración, origen de infección ni familia de malware.
- RAR/7z, memoria, rootkits y telemetría histórica pueden tener cobertura insuficiente.
- La desinfección de todo el sistema no es una acción de un clic. Es posible que se deba reinstalar Windows desde un medio limpio si se perdió la confianza en el equipo.

## Referencias técnicas

- [Microsoft — Reparse points](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-points-and-file-operations)
- [Microsoft — Symbolic links](https://learn.microsoft.com/en-us/windows/win32/fileio/symbolic-link-effects-on-file-systems-functions)
- [Microsoft — WinVerifyTrust](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [YARA](https://yara.readthedocs.io/en/latest/yarapython.html)
- [psutil](https://psutil.io/api/)
- [pefile](https://pefile.readthedocs.io/)
- [VirusTotal API v3](https://docs.virustotal.com/reference/file-info)
- [MalwareBazaar API](https://bazaar.abuse.ch/api/)
- [PyInstaller](https://pyinstaller.org/en/stable/usage.html)
- [PySide6](https://doc.qt.io/qtforpython-6/)

Documentación anterior: `docs/ARCHITECTURE.md`, `docs/GUI_ARCHITECTURE.md`, `docs/BUILD_WINDOWS.md`, `docs/SECURITY.md`. Para Fase 5 consulta `docs/PHASE5_RECOVERY.md`.

**Para distribuir con seguridad:** resta la compilación nativa en Windows, probar el ejecutable y endurecer ACL y operaciones por handles. Este entregable no acredita esas pruebas. No usar como sustituto de Microsoft Defender.


## Solucion al error 'py no se reconoce' (hotfix del compilador)

`build_windows.ps1` ahora intenta `py -3.11`, `python`, `python3` y `py -3`, ademas de algunas rutas locales de Python. Comprueba la version y que sea **64 bits** antes de crear `.venv`. Si no tienes Python, instala Python 3.11 desde [python.org](https://www.python.org/downloads/windows/) o con `winget install --id Python.Python.3.11 --exact`. Abre otra terminal y ejecuta nuevamente `COMPILAR_EXE_WINDOWS.cmd`.

La correccion solo afecta el proceso de compilacion: no implica una validacion real del `.exe` ni de las funciones de mitigacion en Windows.
