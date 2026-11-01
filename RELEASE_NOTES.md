# Sentinel OneGuard — entrega final de código v0.6.0

**Estado:** paquete de desarrollo completo, preparado para compilación en Windows; **no certificado como antivirus de producción**.

## Contenido de la entrega

- Núcleo multimotor: hash SHA-256, YARA, PE/DLL, archivos comprimidos, procesos/red, persistencia y scripts.
- Interfaz PySide6 oscura con logo PNG e icono ICO de Sentinel OneGuard, wizard de consentimiento, resultados, historial y panel de investigación.
- Mitigación experimental con confirmaciones explícitas: cuarentena/restauración de archivos, exclusiones SHA-256, acciones de proceso y Run/RunOnce HKCU.
- Informes HTML y CSV, SQLite, configuración y pruebas sintéticas.
- `COMPILAR_EXE_WINDOWS.cmd`: compilación guiada en Windows 10/11 con Python 3.11 x64.
- `build_windows.ps1`: pruebas y build PyInstaller `--onefile --windowed` con UAC e icono.
- `VERIFICAR_EXE_WINDOWS.ps1`: verificación offline del PE resultante, sin ejecutarlo.
- Workflow `/.github/workflows/windows-exe.yml` para compilación manual en un repositorio privado propio.

## Verificaciones del entorno de entrega

- `pytest` y `compileall` se ejecutan en el entorno de preparación Linux.
- Las comprobaciones que dependen de PySide6, YARA y APIs nativas Windows deben repetirse en Windows; omisión no equivale a aprobación.
- El EXE solo puede darse por compilado cuando exista `dist/SentinelOneGuard.exe` y pase `tools/verify_windows_exe.py` en Windows.
- El EXE será **sin firma digital**, salvo que el usuario lo firme posteriormente con un certificado legítimo.

## Restricciones importantes

- No hay análisis continuo, driver antimalware ni garantía de detección de nuevas amenazas.
- Los comprimidos cifrados, RAR sin backend, algunos 7z, rootkits y memoria protegida pueden quedar sin cobertura suficiente.
- Las reglas incluidas son sintéticas para validar el pipeline, no una base de inteligencia antimalware exhaustiva.
- No ejecutar mitigaciones en un ordenador comprometido sin validación previa en VM y copia de seguridad. Las operaciones con rutas elevadas tienen riesgos de concurrencia y las ACL no están verificadas en Windows.
- Eliminar un stealer no revoca contraseñas, sesiones o cookies ya expuestas. El escáner no puede certificar que el sistema esté limpio.

**Documentación:** `README.md`, `docs/BUILD_WINDOWS.md`, `docs/SECURITY.md`, `docs/PHASE5_RECOVERY.md`.
