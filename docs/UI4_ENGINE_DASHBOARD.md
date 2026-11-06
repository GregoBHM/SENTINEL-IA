# Sentinel OneGuard — UI 4.0, incremento 1: motores visibles

## Estado y objetivo

La primera parte del rediseño presenta los motores en el panel **Análisis**
sin abrir un diálogo secundario. Conservar todos los controles existentes
(Inicio, Análisis, Hallazgos, Investigación, Historial, Ajustes y Cuarentena),
la política de consentimiento y las respuestas únicamente autorizadas.

## Implementación

- `ui/engine_overview.py` dibuja una tabla de hasta 24 motores distintos
  registrados por inventario y métricas, con columnas Estado, Intentos,
  Finalizadas, Omitidas y Señales. No ejecuta análisis ni acciones de respuesta.
- `ui/window.py` lo incorpora a la pantalla Análisis y actualiza las filas
  cuando llegan los eventos `engine_inventory` o `performance`.
- `_prepare_live_scan` limpia el panel al iniciar otro análisis, para no
  mezclar métricas de sesiones distintas.
- `ui/theme.py` ofrece un panel oscuro diferenciado, acentos cian y estados
  legibles con colores accesibles. Se conserva el diálogo técnico detallado.
- `tests/phase4/test_engine_overview_ui4.py` comprueba estados de motores,
  diferencias entre preparado y ejecutado, ausencia de datos y cambio de sesión.

## Semántica de estados

- **Preparado**: el módulo se instanció; no significa que haya inspeccionado nada.
- **Invocado**: hubo intentos registrados; las comprobaciones finalizadas se
  muestran por separado.
- **Con omisiones / errores**: análisis parcial; no representa una detección.
- **No solicitado**: autorización no concedida para ese módulo.
- **No disponible / Inventario parcial**: verificar la cobertura; nunca indicar
  que un sistema está libre de malware por ausencia de señales.

## Condiciones para revisión

1. `python -m pytest -q tests/phase4/test_engine_overview_ui4.py`.
2. Suite completa y `windows-pr-validation` para PySide6 y PyInstaller x64.
3. Comprobar la pantalla en una sesión Windows **interactiva** con tamaño
   mínimo de ventana y fuentes del equipo, además de screenshots CI offscreen.
4. No fusionar automáticamente ni publicar un release basándose solo en CI.

## Próximos incrementos UI

- Jerarquía del dashboard y tarjetas de estado a partir de sesiones reales.
- Investigación, resultado por archivo y cobertura por categoría.
- Alertas y correcciones de errores con textos útiles y verificables.
- Accesibilidad (contraste, foco, zoom), responsividad y revisión visual nativa.
- Pruebas conjuntas con motores, controles de pausa/cancelación y escenarios
  de fallo, sin acciones automáticas de mitigación.
