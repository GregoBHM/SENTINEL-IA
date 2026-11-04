# Sentinel OneGuard 2.0 — Etapa 3C: detección de formatos y cobertura en comprimidos

## Objetivo

Reconocer contenedores soportados aunque estén renombrados y ofrecer evidencia verificable de qué miembros se inspeccionaron realmente. Todas las operaciones siguen siendo **solo lectura**, locales y con límites de bytes, entradas, profundidad y tiempo. Ningún miembro se ejecuta ni se extrae a una carpeta del equipo.

## Identificación de formato

`core/file_formats.py` comprueba una cabecera pequeña y reconoce ZIP (PK), RAR4, RAR5 y 7z. Cuando la extensión coincide con otro formato pero la cabecera es válida, la **cabecera prevalece**. Si no hay una cabecera reconocible pero la extensión es `.zip`, `.rar` o `.7z`, se intenta el parser correspondiente y se registra una limitación explícita cuando falla.

Esto no cubre todos los formatos ni todos los archivos autoextraíbles (por ejemplo, ZIP con un encabezado ejecutable por delante). No se afirmará que un archivo fuera de estos casos esté libre de un contenedor.

## Evidencia de miembros y motores

`ArchiveEngine.scan_with_coverage` retorna hallazgos y registros inmutables `ArchiveMemberCoverage`. Los registros se capturan en contexto local por worker: el objeto compartido de `ArchiveEngine` no acumula datos entre sesiones paralelas.

| Estado | Interpretación |
|---|---|
| `inspected` | Se llamó a la inspección compatible para los bytes accesibles, sin limitaciones observadas en ese miembro; **no implica limpieza garantizada** |
| `partial` | Se inspeccionó una parte del contenido o faltaron comprobaciones |
| `uninspected` | El contenido del miembro no pudo procesarse (cifrado, tamaño, profundidad, error, o 7z sin worker aislado) |

Cada registro conserva el nombre interno, formato, profundidad, bytes realmente extraídos a memoria, comprobaciones intentadas y razón. La tabla SQLite `scan_archive_members` guarda resultados solo en el equipo, por sesión y contenedor. No se realiza sincronización Cloud. La escritura comparte transacción con el estado de motores por objetivo. La interfaz **Por archivo → Ver contenido comprimido** permite consultar hasta 500 registros de una sesión existente o del historial.

Las limitaciones de archivo interno continúan visibles como incidencias, pero no cuentan como detecciones de malware en el agregador. El escáner emite **un aviso agrupado por contenedor** (`SCAN.ARCHIVE.PARTIAL`) con recuentos de miembros no inspeccionados y parciales; el contador «Cobertura parcial» cuenta el contenedor afectado una vez, no una amenaza por miembro. Los motivos y nombres internos siguen disponibles en SQLite y «Ver contenido comprimido». Un registro de cobertura no modifica la política de mitigación.

## Casos especiales

- ZIP anidados se recorren por cabecera, incluso con nombre `.dat` o `.unknown`, sujetos a límites compartidos.
- RAR requiere soporte del backend externo: cuando falta o falla, se informa cobertura parcial; no se inventa contenido inspeccionado.
- 7z **solo inventaría metadatos** en esta fase y marca los miembros como no inspeccionados. No se activará la extracción en proceso hasta contar con worker aislado y límites de recursos efectivos.
- PE dentro de ZIP se reconoce por cabecera `MZ`; un PE con estructura inválida genera omisión estructural, no análisis exitoso.
- Scripts internos con extensiones reconocidas se limitan por `max_script_bytes`; superarlo genera una limitación de cobertura.
- La cobertura de reglas YARA depende del backend seleccionado y de su disponibilidad. Los bytes de miembros son inspeccionados en memoria y bajo límites.

## Limitaciones conocidas y próxima mejora

1. La cobertura por miembro indica etapas ejecutadas, no el porcentaje de bytes de todos los tipos posibles inspeccionados.
2. Entradas duplicadas con exactamente el mismo nombre interno comparten clave local de almacenamiento y requieren un identificador por índice en una etapa posterior.
3. Los análisis de formatos ZIP autoextraíbles y los contenedores poliglota necesitan enrutamiento adicional; el reconocimiento por firma es una pista de formato, no prueba suficiente de seguridad.
4. Los miembros con nombre malicioso no se extraen al disco, pero su nombre queda registrado como evidencia local. No se envía a terceros.
5. ZIP descomprimidos tienen límites; **7z/RAR requieren evaluar aislamiento por proceso y cancelación efectiva** antes de afirmar cobertura profunda.
6. Los riesgos de corrupción del contenedor, límites de parsing, acceso a archivos y falsos positivos todavía deben probarse en Windows con más fixtures representativos.

## Validaciones de aceptación

- Reconocer ZIP/RAR4/RAR5/7z por los primeros bytes incluso si su extensión es falsa.
- Conservar el fallback por extensión sin reportar archivos corruptos como exitosos.
- Demostrar inspección de ZIP anidado renombrado, y omisiones de contenido cifrado o demasiado grande.
- Comprobar el aislamiento de los registros de miembros entre workers concurrentes.
- Registrar miembros de 7z como no inspeccionados, no como detección.
- Migrar SQLite sin destruir el historial; consultar la evidencia desde la interfaz.
- Ejecutar pruebas unitarias, GUI Qt, empaquetado PyInstaller y pruebas de recursos Windows antes del merge.
