# Sentinel OneGuard 2.0 — Etapa 3D.1: relaciones respaldadas por evidencia

## Propósito

La interfaz **Investigación** puede mostrar un listado de relaciones extraído de la base SQLite de una sesión. Es un inventario de conexiones **observadas y documentadas**, no un grafo de infección reconstruido, ni un dictamen forense.

Las relaciones son **solo lectura**: no ejecutan binarios, no abren archivos sospechosos, no descargan muestras, no cambian el registro y no envían datos a la nube.

## Qué relaciones son verificables

| Origen de datos | Relación | Lo que realmente demuestra |
|---|---|---|
| `findings` | Objetivo → hallazgo | El escáner guardó un hallazgo para ese objetivo |
| `evidence` | Objetivo → motor/regla | El motor devolvió una observación almacenada |
| `scan_archive_members` | Contenedor → miembro | El parser enumeró una entrada interna; su cobertura puede ser parcial o inexistente |
| `scan_coverage` | Objetivo → comprobación limitada | Un motor registró una omisión o limitación |
| `scan_targets` | Archivo ↔ archivo por SHA-256 idéntico | Los hashes informados por el escáner coinciden; no significa infección ni propagación |
| `evidence.details.executable_path` | Objetivo → ruta declarada | Un motor documentó esa ruta durante el análisis; no confirma ejecución actual |

Se guarda la fuente de cada relación (tipo de registro, motor, regla o ID de evidencia) y se muestran los motivos de cobertura. Los mensajes distinguen datos que permiten una conclusión de los que solo justifican una investigación adicional.

## Alcance de la implementación

- `core/evidence_trace.py`: consultas SQL acotadas a un `session_id` seleccionado, con límite configurable de 1 a 500 relaciones y detección de reportes truncados. No utiliza archivos de disco ni servicios de red.
- `ui/evidence_trace.py`: ventana de tabla con filtros por relación, texto de procedencia y advertencias explícitas.
- `ui/window.py`: acción «Explorar relaciones y evidencias locales» en Investigación. Puede abrir la sesión actual o una seleccionada en Historial.
- Compatibilidad con las tablas de las etapas 3A/3C sin introducir nuevas migraciones.
- Las rutas y hashes no aparecen en registros públicos de GitHub ni se sincronizan con la nube.
- No se alteran los puntajes de riesgo ni la política de mitigación.

## Límites y advertencias

1. Una ruta declarada por un motor puede estar desactualizada, no existir o haber sido modificada después del escaneo.
2. Tener un archivo idéntico por SHA-256 no evidencia propagación ni explica cómo llegó al sistema.
3. Las conexiones de red actuales no demuestran exfiltración, persistencia ni comunicación maliciosa anterior.
4. El registro actual no incorpora telemetría histórica de Windows ni permite demostrar una cadena causal temporal, punto inicial de infección o alcance de robo de información.
5. Los límites de consultas protegen la interfaz. Cuando el informe está truncado, no debe interpretarse como exhaustivo.
6. Los hallazgos y puntajes son información de un sistema experimental y requieren verificación con otros instrumentos y muestras autorizadas.

## Siguientes etapas recomendadas

- **3D.2**: modelos tipados de evidencias de procesos y persistencia; relaciones con identidades de proceso verificadas (PID + tiempo de creación + hash) y límites temporales.
- **3D.3**: evaluar un motor de capacidades como capa en aislamiento de proceso, con límites y corpus autorizado; nunca derivar malware confirmado solo por capacidad.
- **3D.4**: generar informes locales explicables HTML/JSON con separación de hechos, hipótesis, limitaciones y acciones propuestas.
- **3D.5**: medir falsos positivos/negativos y tiempos de correlación con conjuntos controlados, sin asegurar cifras predictivas exactas.

## Validación

Pruebas unitarias de integración SQLite, archivos ZIP, reglas sintéticas, ruta declarada, igualdad de SHA-256, sesiones aisladas, truncación y GUI Qt; workflow Windows con build one-file, marca, UAC y esquema incluido. Se requiere revisión manual de la vista en Windows antes de Release.
