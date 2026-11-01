# Sentinel OneGuard — Fase 5: Mitigación y recuperación

## Objetivo

Esta etapa añade **acciones manuales y explícitas**, no limpieza automática ni un certificado de máquina sana.

**Amenazas activas o sospecha de compromiso real:** aísla la máquina, haz copia de datos no ejecutables, cambia credenciales en otro dispositivo confiable y revisa Microsoft Defender. No ensayes las acciones de esta versión con una infección real.

## Capacidades implementadas

| Función | Comportamiento y alcance |
|---|---|
| Cuarentena | Solo un hallazgo de archivo de disco con SHA-256 registrado y nueva comprobación de integridad; movimiento mismo volumen, UUID y `.blob`. |
| ACL | En Windows intenta remover permisos heredados en `%ProgramData%/SentinelOneGuard/Quarantine`, permitir SYSTEM y Administradores y denegar ejecución en blobs. **Sin validación nativa aún**. En Linux de prueba: `0700/0600`. |
| Restaurar | Nunca sobrescribe destinos. En Windows se requiere `icacls /reset` para recuperar ACL del directorio; si falla se intenta rollback y se marca estado para revisión. |
| Eliminar | Solo se permite eliminar el `.blob` de un objeto que ya estaba en cuarentena, con dos pasos de confirmación. No permite eliminar archivos arbitrarios. |
| Excluir | Acepta SHA-256 confirmado y justificación. Mantiene toda la evidencia almacenada para auditoría. |
| Terminar proceso | Solo en Windows, instancia de PID+tiempo de arranque+ejecutable; rechaza nombres críticos y ubicaciones protegidas; no fuerza `kill`. |
| Run / RunOnce | Solo `HKCU`, valor registrado en la evidencia y comando sin modificaciones desde el escaneo, con backup SQLite para restaurar. No modifica HKLM, servicios ni tareas. |
| HTML / CSV | Reportes locales por sesión. Escapa contenido HTML, neutraliza fórmulas de hoja de cálculo y evita sobrescribir informes. |
| Guía de respuesta | Explica qué hacer y cuándo considerar reinstalación; la aplicación no declara un sistema limpio. |

### Operaciones prohibidas

- No ejecutar una muestra ni abrirla en aplicaciones asociadas.
- No modificar el sistema, servicios, drivers, cuentas, claves HKLM, carpetas Windows/Program Files/ProgramData, ni archivos con enlaces o hardlinks.
- No borrar ni terminar nada sin consentimiento; las llamadas backend requieren frases de aprobación literales.
- No sobrescribir archivos restaurados ni informes.
- No subir contraseñas, cookies, archivos ni informes a un servidor.

### Seguridad que falta para producción

**PENDIENTE**: ejecutar en una VM Windows 10 y 11 con snapshot, validar ACL/restore UAC, hacer pruebas controladas de carrera de rutas/junctions/hardlinks y errores de disco. Un proceso elevado con acceso a rutas controladas por usuarios admite TOCTOU (time-of-check/time-of-use) incluso con comprobaciones repetidas. Una versión sólida debe mover cambios de filesystem a un broker con privilegios mínimos y validación por *handles* nativos en lugar de rutas, además de aislar decodificadores y mantener una DB protegida contra usuarios no elevados.

**PENDIENTE**: análisis forense temporal completo (eventos Sysmon, cambios de configuración y conexiones históricas), protección frente a rootkits, transacciones Windows de recuperación extendida, RAR/7z profundo aislado y evaluación con un corpus representativo.

## Uso con datos sintéticos

1. En **VM limpia** crea `synthetic_fixture.txt` mediante `tools/create_synthetic_test.py`.
2. Obtén su digest con `tools/show_sha256.py` y registra firma local usando `main.py add-signature`.
3. Analiza el archivo desde la GUI. Confirma que es una muestra de prueba.
4. Para probar la cuarentena manual con datos inocuos: selecciona el hallazgo, confirma `CUARENTENA` y verifica el resultado en la pestaña Cuarentena.
5. Antes de restaurar, verifica el destino original; confirma `RESTAURAR` y vuelve a analizar. No ejecutes el archivo.
6. Exporta HTML y CSV desde Hallazgos.
7. Solo en una VM desecharle ensaya una entrada HKCU Run inofensiva y verifica la restauración. Nunca uses como prueba una entrada del sistema real.

**Nota**: La cuarentena Windows puede fallar por permisos o política de la máquina. Eso debe informarse como falla, jamás como limpieza exitosa.

## Fuentes de seguridad

- Microsoft, Reparse points and file operations: https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-points-and-file-operations
- Microsoft, Symbolic link effects: https://learn.microsoft.com/en-us/windows/win32/fileio/symbolic-link-effects-on-file-systems-functions
- Microsoft, Hard links and junctions: https://learn.microsoft.com/en-us/windows/win32/fileio/hard-links-and-junctions
- Microsoft, MoveFileEx: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw
- MITRE ATT&CK, Registry Run Keys / Startup Folder: https://attack.mitre.org/techniques/T1547/001/
- Microsoft Defender Offline: https://support.microsoft.com/windows/help-protect-my-pc-with-microsoft-defender-offline
