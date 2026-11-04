# Sentinel OneGuard 2.0 — Etapa 3B: YARA-X opcional y comparación reproducible

## Alcance y límites

La versión de producción usa **YARA clásico** (`yara-python`). Esta etapa añade **YARA-X solo para pruebas controladas y selección explícita**, no hace cambios automáticos en clientes y **no incluye YARA-X en el EXE público**. La rueda opcional se instala únicamente en los runners de validación de PR después de compilar el ejecutable.

La API de YARA-X en Python es distinta de la de yara-python: `Compiler.add_source`, `Scanner.scan_file`, `Scanner.scan` y `ScanResults.matching_rules`. Cada escaneo instancia su propio `Scanner` y usa un límite temporal configurable. Los archivos no se ejecutan ni se envían a servicios remotos.

## Compatibilidad y trazabilidad

- Ambas implementaciones exponen `match_bytes(data)` y retornan `RuleMatch`, con identificador de regla, espacio de nombres, metadatos y etiquetas disponibles.
- El análisis de contenido dentro de ZIP usa esta interfaz y ya no accede a un atributo privado exclusivo de YARA clásico.
- Los resultados `Finding` mantienen la semántica de metadatos `risk_score`, `confidence`, `test_only`, `threat_type`, `mitre` y `description`; `details.backend` indica qué implementación los produjo.
- El motor sigue llamándose `yara` para mantener la misma categoría y no contar dos escaneos como dos evidencias independientes.
- Si falta la biblioteca, falla la compilación o existen reglas incompatibles, se reporta explícitamente que YARA no está disponible; **no se invoca YARA clásico a escondidas como sustituto de YARA-X**.
- Por seguridad y reproducibilidad, el compilador experimental no permite instrucciones `include`. Los packs que las requieren se marcarán como incompatibles hasta definir una política de includes restringidos y auditados.
- Los límites de tamaño y los fallos de formato permanecen visibles. La biblioteca experimental es un motor nativo y necesita pruebas en Windows real.

## Uso desde fuentes para evaluación

Instalar primero las dependencias originales, luego la opcional:

```powershell
python -m pip install -r requirements.txt
python -m pip install --only-binary=:all: yara-x==1.22.1
```

La configuración por defecto es:

```toml
[scanner]
yara_backend = "classic"
```

Para optar por YARA-X, cambiar a `"yarax"` al construir el `ScanConfig`, cargar un TOML mediante `load_config_file` en un consumidor compatible o usar `ONEGUARD_YARA_BACKEND=yarax` al lanzar la GUI **desde fuentes**. En Windows PowerShell:

```powershell
$env:ONEGUARD_YARA_BACKEND = "yarax"
python run_gui.py
```

No hay un selector público en el instalador ni un paquete dinámico que descargue componentes durante la ejecución. El EXE experimental CI sigue compilado solo con los requisitos de producción; para distribuir YARA-X de forma oficial habrá que revisar licencias, dependencias, tamaño y empaquetado.

## Benchmark que ejecuta CI

```powershell
python -m tools.benchmark_yara_backends --files 24 --rounds 3
```

- Crea archivos **inofensivos** reproducibles, con y sin un marcador sintético; no utiliza muestras reales de malware.
- Usa **el mismo conjunto de reglas** para ambos motores y compara por archivo las coincidencias mediante identificadores.
- Mide tiempo de compilación y varias pasadas de tiempo de análisis, alternando el orden entre motores para reducir sesgo de caché.
- Si hay alguna diferencia, retorna un error y registra las rutas sintéticas del desacuerdo; no silencia reglas incompatibles.
- Guarda reporte JSON como artefacto `sentinel-oneguard-yarax-evaluation` en GitHub Actions.

**La equivalencia sobre estos fixtures no demuestra precisión antivirus.** No se reivindica mayor rapidez o fiabilidad hasta comparar conjuntos más representativos, formatos difíciles, reglas verificadas, archivos comprimidos y Windows de distintas capacidades. El conjunto de reglas incluido es de **prueba**; no pretende reconocer familias reales de malware.

## Puertas de aceptación

1. Windows ejecuta los tests de ambas bibliotecas sobre los fixtures sintéticos.
2. Coinciden los identificadores de reglas aplicadas y sus puntuaciones en los ejemplos de prueba.
3. Se mantiene la detección YARA clásica en archivos y miembros ZIP.
4. El backend opcional se desactiva sin causar falsos éxitos al faltar la rueda o reglas.
5. El empaquetado clásico con logo, UAC, SQLite y reglas se conserva.
6. Los resultados tienen procedencia del backend y distinguen omisión, error, no aplicable y hallazgo.
7. El PR permanece en borrador hasta revisar estabilidad, benchmarks, límites de consumo y compatibilidad con reglas reales permitidas.

## Etapa 3C posterior

Clasificación de formatos por firma binaria para ZIP/7z/RAR y scripts, registro de cobertura por miembro de archivos comprimidos, límites y procesos aislados para analizadores complejos. Después, análisis de capacidades y correlación (fase 3D).
