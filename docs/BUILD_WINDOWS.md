# Generar SentinelOneGuard.exe con logo en Windows

**Estado:** fuente lista para compilación reproducible; la compilación de Windows no se pudo realizar en el entorno Linux usado para preparar este paquete. Por eso **no contiene un EXE listo para abrir**. El ejecutable solo debe considerarse validado después de ejecutar las pruebas en Windows.

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

El script detiene la compilación si fallan pytest, la apertura de una ventana Qt de prueba o el análisis del PE generado. En Windows el empaquetado puede requerir adaptaciones según versiones de librerías y antivirus: **no se ha probado esa fase aquí**.

## Método B: GitHub Actions (sin Python local)

1. Sube el contenido del ZIP a **tu propio repositorio privado** de GitHub. No subas API keys ni bases de datos con información personal.
2. En **Actions**, elige `Build branded Windows executable` y pulsa `Run workflow`.
3. Al completar el workflow en un runner de Windows, descarga el artefacto `SentinelOneGuard-Windows-EXE` desde la pestaña Actions.
4. Comprueba su SHA-256 antes de distribuir.

Este workflow se activa solo manualmente. No publica binarios ni crea una release pública por sí mismo.

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
