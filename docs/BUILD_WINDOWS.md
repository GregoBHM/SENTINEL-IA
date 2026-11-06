# Generar SentinelOneGuard.exe con logo en Windows

**Estado:** GitHub Actions compila el ejecutable en un runner Windows 64 bits y lo publica como artefacto descargable cuando las pruebas terminan correctamente. El archivo continúa siendo **experimental y sin firma digital**. La comprobación del empaquetado no equivale a una validación de desinfección.

## Qué se va a obtener

- `dist/SentinelOneGuard.exe`: aplicación de un solo archivo (`onefile`) para Windows 10/11, x64, sin ventana de consola, con icono de escudo y versión en Propiedades del archivo.
- `dist/SentinelOneGuard.sha256.txt`: hash para comprobar integridad.
- Manifiesto UAC `requireAdministrator`: Windows solicita permisos elevados al abrirla. **No significa que el programa esté firmado digitalmente** ni que Microsoft lo reconozca como confiable.
- El mismo logo en el encabezado de la interfaz, icono de ventana, barra de tareas y archivo EXE.

## Método A: compilación local en Windows 10/11 x64

1. Prueba primero en Windows Sandbox o una VM con snapshot. Instala Python **3.11 x64** desde python.org; marca *Add Python to PATH* e instala Python Launcher (`py`).
2. Descomprime el ZIP del código en una carpeta normal, por ejemplo `Documentos\\OneGuard`. **No ejecutes archivos del proyecto desde un equipo sospechoso.**
3. Abre **PowerShell** en esa carpeta.
4. Ejecuta: `powershell -NoProfile -ExecutionPolicy Bypass -File .\\build_windows.ps1`
5. Si las pruebas y comprobaciones de recurso pasan, el script crea `dist\\SentinelOneGuard.exe` y su hash.

Las dependencias se instalan desde pip; requiere acceso a Internet durante la compilación. El EXE final contiene el runtime de Python, las librerías usadas y las reglas de ejemplo. No requiere instalar Python en la PC donde se ejecuta.

El script detiene la compilación si fallan pytest, la comprobación Qt o el análisis del PE generado y sus recursos internos. El análisis completo y la mitigación aún deben validarse en una máquina Windows de pruebas.

## Método B: GitHub Actions (automático, sin Python local)

**El repositorio genera el EXE automáticamente con cada push a `main`.** También puedes lanzar la compilación manualmente:

1. Abre https://github.com/GregoBHM/SENTINEL-IA/actions/workflows/windows-exe.yml.
2. Si acabas de realizar un push a `main`, abre la nueva ejecución de **Build branded Windows executable**; no necesitas pulsar nada. Para crearla manualmente, selecciona **Run workflow** y la rama `main`.
3. Cuando la ejecución esté en verde, entra y abre **Artifacts** al final de la página.
4. Descarga `SentinelOneGuard-Windows-EXE`, descomprime el ZIP y extrae `SentinelOneGuard.exe` junto con `SentinelOneGuard.sha256.txt`.
5. En PowerShell puedes comprobar el hash con `Get-FileHash -Algorithm SHA256 .\\SentinelOneGuard.exe` y compararlo con el archivo `.sha256.txt`.

El workflow ejecuta tests, prueba de inicio Qt, empaqueta recursos SQLite / YARA, verifica el icono y UAC, e inspecciona que `db/schema.sql` esté dentro del ejecutable. Los artefactos se conservan 30 días; para distribuir versiones estables a futuro sería necesaria una política de releases y firma de código.

**Aviso:** no descargues ni ejecutes la versión antigua si produce `_MEI.../db/schema.sql` no encontrado; ese error significa que el EXE no incluye el esquema. Utiliza una ejecución nueva de `main` cuyo workflow termine correctamente. Antes de analizar una PC comprometida, prueba en una VM con snapshot y evita la mitigación experimental en dispositivos reales.

## Método C: GitHub Releases automáticos desde main

El workflow `.github/workflows/release-windows.yml` publica una **pre-release
experimental versionada** tras cada push a `main`, siempre que pasen
pytest, smoke de GUI, la compilación PyInstaller y las verificaciones de
recursos, manifiesto UAC e icono. Una PR abierta no publica binarios.

El workflow usa el prefijo `vX.Y.Z-beta.` de `RELEASE_VERSION.txt` y
crea un tag distinto por ejecución: para evitar reutilizar versiones, el
sufijo es `1000 + github.run_number`. Por ejemplo, un proyecto con prefijo
`v0.6.0-beta.` puede producir `v0.6.0-beta.1010`. **No es un contador
manual de versiones ni una versión estable.** El nombre podría cambiar si
se modifica la política de numeración en el futuro.

1. Fusiona primero la PR aprobada en `main`.
2. Abre [Actions → Publish versioned Windows prerelease](https://github.com/GregoBHM/SENTINEL-IA/actions/workflows/release-windows.yml).
3. Comprueba que todas las etapas terminaron correctamente.
4. Descarga el nuevo `SentinelOneGuard.exe` y
   `SentinelOneGuard.sha256.txt` desde
   [Releases](https://github.com/GregoBHM/SENTINEL-IA/releases).
5. Verifica el SHA-256 antes de ejecutarlo en una VM con snapshot.

Las publicaciones son nuevas versiones inmutables por convención; nunca
se sobrescribe un Release anterior. **Cada push a main provoca otra
compilación Windows** además de `windows-exe.yml`, por lo que aumentan los
minutos de GitHub Actions. Las pre-releases experimentales todavía requieren
prueba interactiva para su uso real y no deben confundirse con un programa
de seguridad certificado.

También puedes ejecutar el workflow manualmente desde `main` con un tag
nuevo `vX.Y.Z-beta.N` o publicar un tag válido `v*`, sin reemplazar
publicaciones existentes. El modo manual sin versión utiliza
`RELEASE_VERSION.txt` y puede ser rechazado si esa versión ya existe.

**GitHub Packages no es un canal de distribución EXE nativo**: el
`.exe` se ofrece como asset de Releases y como artefacto temporal de
Actions. Publicar un contenedor en GHCR sería un producto distinto.

## Validación de seguridad previa a su uso

- Verifica en Windows 10 y Windows 11 que el logo aparece en el EXE, la ventana y la barra de tareas.
- Comprueba la petición UAC y el diálogo de consentimiento dentro del programa.
- Ejecuta análisis personalizados sobre archivos **sintéticos inofensivos**, con red desactivada.
- Comprueba que se crean registros SQLite, que el dashboard responde y que los estados parciales se reportan.
- Asegúrate de que las fuentes YARA/PE/rarfile están disponibles; registra cualquier cobertura incompleta.
- Revisa el análisis en Microsoft Defender; no lo desactives para ejecutar el programa.
- Considera firmar el EXE con una credencial Authenticode legítima si se pretende distribuir a terceros. El icono **no** equivale a firma digital ni evita SmartScreen.

## Cobertura y límites actuales

Este build empaqueta la **Fase 5**. Añade cuarentena y respuesta manual bajo confirmación, y reportes HTML/CSV. **Estas acciones Windows no han sido validadas en el entorno de desarrollo**: no las utilices fuera de una VM hasta verificar ACL y restauración. Las reglas iniciales son sintéticas y no equivalen a una base antimalware de producción. No sirve para dar de alta un equipo comprometido ni sustituye Microsoft Defender. Elevar todo el proceso implica un riesgo adicional al analizar contenido no confiable; una versión productiva debe usar procesos auxiliares con privilegios limitados y pedir elevación por operación.

## Documentación oficial

- PyInstaller: https://pyinstaller.org/en/latest/usage.html
- PyInstaller (no es cross-compiler): https://github.com/pyinstaller/pyinstaller
- PySide6 / despliegue: https://doc.qt.io/qtforpython-6/deployment/deployment-pyinstaller.html
- Windows UAC y firma de código: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works
