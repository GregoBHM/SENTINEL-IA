# UI 4.0 — Resumen real de la sesión y revisión de alertas

El panel Inicio muestra los tres contadores de la **última sesión registrada**
(archivos evaluados, objetivos con hallazgos y errores), con el estado de esa
sesión y un aviso de limitaciones. Nunca afirma que el dispositivo esté sano.

La pantalla Hallazgos incorpora un resumen de **las filas realmente cargadas**
en la tabla: alertas altas/críticas no excluidas, alertas con riesgo orientativo
mayor o igual a 20 y hallazgos excluidos. El número visible puede ser menor
que el total almacenado: HistoryRepository limita los resultados por sesión.

El área de Inicio es desplazable para no ocultar opciones en ventanas pequeñas.
La interfaz conserva los controles de respuesta y confirmaciones ya existentes.

## Verificación
`python -m pytest -q tests/phase4/test_ui4_home_results.py`

Requiere además ejecución completa en Windows, inspección visual interactiva y
comprobación de accesibilidad. Se mantienen las advertencias sobre cobertura
parcial, falsos positivos/negativos y que ausencia de hallazgos no equivale
a Windows limpio.
