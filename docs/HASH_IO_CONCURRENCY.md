# Etapa 2/5 — Control de I/O durante hashing

## Implementación

`ScanConfig.max_hash_io_workers` (1–8, predeterminado 2) limita las
lecturas completas simultáneas realizadas por el observador de identidad y
`HashEngine` dentro de una sesión. Es independiente de `max_workers` y
`max_pending`, que ya limitan la cola de análisis global.

La implementación no restringe las lecturas de cabeceras pequeñas, ni las de
YARA, PE, scripts y descompresores. **Por ello no es un presupuesto completo
de disco**. Tampoco limita todos los bytes leídos ni garantiza velocidad.

Configuración TOML:

```toml
[scanner]
max_workers = 4
max_pending = 8
max_hash_io_workers = 2
```

## Benchmark reproducible

```powershell
python -m pytest -q tests/test_hash_io_concurrency_v2.py
python -m tools.benchmark_hash_io --files 40 --size-kib 128
```

El benchmark utiliza archivos sintéticos inocuos, prueba secuencialmente
1, 2 y 4 lecturas simultáneas y registra tiempos reales; puede verse
afectado por la caché del sistema operativo y otras tareas concurrentes.
No extrapolar cifras a un equipo infectado ni a archivos grandes.

## Validación exigida

Suite completa y build de Windows CI, pruebas en Windows 10/11, estrés con
discos HDD/SSD, cancelación y uso de memoria. No fusionar sin evidencia de que
ninguna comprobación se pierde o se marca limpia por una limitación de I/O.
