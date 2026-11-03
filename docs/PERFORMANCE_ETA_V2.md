# Sentinel OneGuard 2.0 — Etapa 2: rendimiento y estimación orientativa

## Objetivo
Observar el coste real de cada motor en Windows antes de cambiar algoritmos de detección. El resultado **no** debe confundir velocidad con precisión ni presentar un tiempo restante exacto.

## Implementado
- `core/performance.py`: cronómetro monotónico independiente del hilo Qt, medición agregada de tareas y llamadas a motores, tiempo de pausa solicitado, tamaño de archivo de entrada y ritmo observado.
- `ScannerManager._scan_target`: instrumentación `perf_counter()` por invocación; clasifica éxito, omisión y error sin alterar las detecciones.
- `ScanPerformanceMonitor.snapshot`: intervalos conservadores de tiempo para los objetivos *ya descubiertos*. Cuando continúa el descubrimiento, la etiqueta dice **«Cola conocida»**, no «Tiempo restante global».
- `ScanEvent(kind="performance")`: actualizaciones de mediciones limitadas aproximadamente a una por 0,8 segundos; `complete.performance` conserva el estado final aunque se pierdan eventos intermedios.
- `scan_engine_metrics` SQLite: resumen por sesión y motor, sin rutas personales; bases existentes se conservan, la tabla se crea al inicializar el esquema existente.
- PySide6: muestra intervalos y un detalle por motor de duración acumulada, media por comprobación, omisiones, errores y tamaño de entradas.
- Compatibilidad: todas las operaciones de mitigación siguen exigiendo confirmación y ningún motor requiere Internet.

## Definiciones de métricas

| Campo | Interpretación correcta |
|---|---|
| `checks` | Número de invocaciones al motor, incluidas las omitidas y fallidas |
| `completed` | Invocaciones que terminaron sin excepción |
| `skipped` | Omitidas intencionadamente por política/límites |
| `errors` | Excepciones del motor |
| `duration_seconds` | Suma de duraciones de invocación; motores concurrentes solapan tiempo |
| `input_size_bytes` | Suma de tamaños nominales de los objetivos presentados al motor, **NO** bytes leídos del disco |
| `throughput_targets_per_second` | Objetivos finalizados divididos por tiempo activo observado, o tasa móvil reciente |
| `eta` | Rango ilustrativo de planificación para cola conocida o para alcance íntegro si terminó el descubrimiento |

## ETA: reglas de honestidad
- Solo mostrar una estimación después de al menos **8 objetivos terminados** y **3 segundos activos**, si hay objetivos conocidos pendientes y una tasa positiva.
- Durante el descubrimiento: `eta.scope="known"` y texto «Cola conocida ... aún se descubren objetivos». **No es una predicción total del análisis**.
- Solo cuando el descubrimiento finaliza puede `eta.scope="full"` aplicarse a la cola final pendiente. No significa que anticipemos errores futuros, bloqueos de Windows o nuevas tareas.
- Rango inicial: 0,6 a 1,8 veces la duración central estimada con velocidad observada. **No es un intervalo de confianza estadístico**.
- No mostrar ETA si hay pausas activas, cancelación, ejecución completada o datos insuficientes.
- La velocidad puede cambiar por formatos, caches, CPU, discos, antivirus y descompresión; los límites pueden requerir ajuste posterior con pruebas etiquetadas.
- Las muestras de sistema que no sean archivos se cuentan como objetivos pero no como bytes físicos del disco.

## Qué no está implementado (siguientes etapas)
- ETA calibrado estadísticamente según tamaño de archivos, tipos, cargas de CPU/disco, profundidad de archivo comprimido o latencias por motor.
- Replanificación de trabajos, prioridad por riesgo, ajuste automático de concurrencia, YARA-X o firmas multipatrón.
- Comparación histórica por fases y calibración posterior de estimaciones con sus errores observados.
- Nuevas funciones de mitigación, escaneo en tiempo real o sincronización Cloud.

## Pruebas de aceptación
1. Sin inventar ETA antes de muestras mínimas.
2. El ETA no se muestra como global mientras se descubren archivos.
3. El tiempo permanece congelado tras terminar y no aparece ETA durante pausa o cancelación.
4. Omisiones de YARA y excepciones se contabilizan por motor, sin convertirse en detecciones.
5. Las métricas SQLite se consultan por sesión y no incluyen rutas individuales.
6. La GUI permanece responsiva; se generan eventos limitados y se utilizan snapshots finales.
7. El workflow Windows comprueba pruebas unitarias, Qt, empaquetado one-file, logo, UAC y `db/schema.sql`.
8. Probar primero en VM, sin activar mitigación experimental en un equipo comprometido.

## Benchmark sintético reproducible

Puedes ejecutar una línea base local, sin archivos maliciosos ni red:

```powershell
python -m tools.benchmark_scanner --files 150 --workers 3
```

El comando crea archivos inofensivos en una carpeta temporal y devuelve un resumen JSON con tasa de archivos/segundo y duraciones del motor Hash. No mide precisión antivirus ni el escaneo de todo Windows. Ejecutarlo en Windows permite establecer una referencia antes de optimizar YARA, PE y la concurrencia.

## Próximos benchmarks propuestos
- 1.000 archivos benignos de tamaños mixtos (sin muestras malware real).
- Archivos PE sintéticos y comprimidos inofensivos con límites aplicables.
- Discos HDD/SSD, perfiles de 1/2/4 workers y 64/128 MiB de límite YARA.
- Evaluar productividad (objetivos/s) junto a cobertura, errores, falsos positivos y CPU.
