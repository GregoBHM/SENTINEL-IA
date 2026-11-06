# Sentinel OneGuard 2.0 — Integración temporal de etapas 1 a 3

Este branch de **verificación** reúne los cambios propuestos en:
- PR #18: UI 4.0, resúmenes de sesiones y hallazgos.
- PR #19: límites de concurrencia de lecturas de hashing y benchmark sintético.
- PR #20: PowerShell codificado UTF-16LE, categorías heurísticas y límites VBA.

## Procedimiento de validación

1. Ejecutar todas las pruebas automáticas y PyInstaller Windows x64.
2. Inspeccionar la interfaz en Windows interactivo (resoluciones y contraste).
3. Probar benignos y muestras sintéticas de scripts/OOXML.
4. Comparar tiempos reales de análisis hash con distinto número de carriles.
5. Revisar falsos positivos, omisiones, memoria y cancelación.

## Estado
Esta rama **no es un release** y no certifica detección real. Evitar fusionarla
si las PR #18–#20 se van a integrar individualmente; el propósito es disponer
de una compilación conjunta para QA, sin alterar `main`.
