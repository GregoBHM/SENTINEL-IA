# Sentinel OneGuard 2.0 — Investigación: cobertura auditable

## Cambios
- `core/investigation_coverage.py` agrega contadores **de la sesión
  seleccionada** utilizando consultas SQL acotadas. No abre archivos,
  modifica el sistema ni se conecta a Internet.
- `ui/evidence_trace.py` muestra una síntesis de cobertura y permite
  filtrar `content_identity` (huellas de ejecutables observadas).
- `core/report.py` incluye una sección de cobertura en el reporte HTML
  local, con escape de contenido y política CSP existente.
- Las pruebas sintéticas validan aislamiento entre sesiones,
  comportamiento con omisiones e informes sin hallazgos.

## Política de interpretación
- `scan_target_engines.success` significa que la invocación del motor
  acabó sin excepción, **no** que el equipo sea seguro.
- `skipped`, `error` y `not_run` cuentan como verificaciones incompletas.
- `scan_archive_members.partial` y `uninspected` son contenido no
  completamente inspeccionado. El motor 7z aún requiere aislamiento.
- Una identidad de archivo `observed` solo significa que se observaron
  bytes en disco. No certifica que fueran los bytes ejecutados.
- Una entrada Run/RunOnce `reference_only` es una referencia configurada,
  **no** prueba de ejecución efectiva.
- Una sesión finalizada con cero alertas o cero omisiones registradas **no**
  demuestra ausencia de malware, persistencia, exfiltración ni robo de datos.
- La ausencia de métricas por objetivo se trata como información insuficiente.

## Aceptación
```powershell
python -m pytest -q tests/test_investigation_coverage_v2.py tests/phase4/test_investigation_coverage_ui_v2.py
python -m pytest -q
```
Requiere PyInstaller y smoke GUI Windows 10/11. No fusionar ni publicar una
versión estable únicamente por aprobar tests sintéticos.

## Aún pendiente para una versión de producción
- Banco de muestras autorizado, benignas/maliciosas, independiente de
  entrenamiento; medir precisión, falsos positivos, falsos negativos y
  cobertura por clases de amenaza.
- Inspección 7z segura en proceso aislado con límites de tiempo/memoria.
- Endurecer Authenticode, reparse points, races, mitigación y reversión
  bajo Windows real, permisos restringidos y fallo de energía.
- QA interactivo, accesibilidad, firma del ejecutable y actualización segura.
- Determinar qué amenazas no pueden remediarse sin reinstalación.
