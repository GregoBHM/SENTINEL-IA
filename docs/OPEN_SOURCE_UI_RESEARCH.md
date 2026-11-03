# Revisión de interfaces open-source para Sentinel OneGuard
Fecha: 2026-11-03. Investigación de referencia, no autorización para copiar código o marca.

## Proyectos examinados

| Proyecto | UI/capacidad observada | Qué aprender | Qué NO copiar |
|---|---|---|---|
| [ClamUI](https://clamui.com/) | Selector de perfiles Rápido/Completo/Personalizado, logs, cuarentena e historial. Capturas publicadas por el proyecto. | Alcance explícito antes de iniciar, controles concisos, gestión clara de perfiles y registro. | Promesas de protección permanente sin motor residente; los componentes GTK no se pueden copiar directamente a PySide6. |
| [Velociraptor](https://docs.velociraptor.app/) | Interfaz investigativa con vistas Artifacts, Results, Log y Notebook, evidencia estructurada y colección. | Separar observación, evidencia original, relación y explicación; tabla -> detalle -> procedencia. | Complejidad operativa de una plataforma multiendpoint en una herramienta personal. |
| [Wazuh](https://wazuh.com/platform/overview/) | Dashboards de eventos y filtros de seguridad. | Resumen por severidad y fuente, filtrar por técnica/estado/hora; cronología cuando existan eventos reales. | Gráficos ficticios, tasas sin datos históricos o SIEM que no existe. |
| [ClamWin](https://github.com/clamwin/clamwin) | GUI nativa Win32 separada del motor ClamAV, pruebas de GUI. | Mantener la presentación desacoplada del motor y probar pantalla y empaquetado. | Importar C++ ni adoptar recursos con licencia incompatible sin revisión. |
| [PyGuard](https://github.com/DrVerzide/pyguard-scanner) | GUI CustomTkinter y escaneo por demanda con YARA/hash y EXE. | Flujo simple archivo/carpeta -> análisis -> resultados -> cuarentena; avisos claros del alcance. | Suponer cobertura antivirus productiva por llevar un EXE. |
| [HORUS](https://github.com/mobinert/HORUS) | Triage en Windows, análisis PE y enriquecimiento opcional de hash en EXE portátil. | Hallazgos explicables por observación, confianza y evidencia. | Usar categorización de riesgo no calibrada como diagnóstico definitivo. |

## Lectura del diseño anterior
Captura enviada por el usuario: fondos opacos detrás de etiquetas, recortes en sidebar, consola demasiado grande, cobertura genérica, fallo SQLite visible como excepción, resultados nulos no concluyentes.

## Nueva dirección visual
- **Marca:** Sentinel OneGuard. Mantener escudo y acento cian; paneles grafito, indicadores de riesgo discretos; no clonar Avast, Defender o ClamUI.
- **Navegación:** Inicio, Analizar, Hallazgos, Investigar, Historial, Cuarentena, Ajustes. Nada de categorías que no existan realmente.
- **Inicio:** estado de última evaluación (fecha, alcance, omisiones) y tarjetas para tipos de escaneo. Nunca «Equipo protegido» basado solo en 0 hallazgos.
- **Análisis:** línea de estado (Prepara / Descubre / Inspecciona / Correlaciona / Finaliza), tiempo observado, pausa, velocidad y objetivo reciente; registros plegables. ETA solo si se conoce un total estable.
- **Resultados:** tabla priorizada por riesgo y confianza, filtros por severidad, fuente, familia, estado; primera fila abre ficha de causa y evidencia. Estado vacío: «No hay hallazgos visibles. Cobertura parcial / revisar errores».
- **Investigación:** línea temporal basada en eventos observados, proceso padre->hijo, hash, rutas, persistencia y conexiones vinculadas cuando existan. Enlaces a evidencia original y MITRE cuando aplique. Causa probable ≠ origen probado.
- **Cuarentena:** contador, estado, hash y fecha, acciones Restaurar/Eliminar con confirmación y trazabilidad, indicadores de protección del sistema. No sugerir limpieza automática.
- **Historial:** duraciones, alcance, exclusiones, errores, hallazgos, reanálisis y comparación solo de métricas persistidas.
- **Ajustes:** claves y privacidad, excepciones, fuentes YARA/versiones, rendimiento, accesibilidad e información del build.

## Design system / validación
- Tipografía Segoe UI con título 26-30px, encabezado 18-22px y cuerpo 12-14px; etiquetas pequeñas no deben ser indispensables para entender contenido.
- Contraste suficiente en estados: nunca codificar severidad únicamente por color.
- Sidebar con etiquetas medidas con QFontMetrics; en anchura reducida, usar scroll en contenido y no recortar controles.
- Evitar fondo aplicado globalmente a QWidget; labels transparentes; QFrame como dueño del fondo de cada tarjeta.
- Consola plegable con máximo de bloques. No refrescar datos de tablas cada evento ni bloquear el hilo GUI.
- QA Windows: 1050x680 y 1390x900, DPI 100%/125%/150%, pantallas Intro/Análisis/Resultados/Investigación/Cuarentena/Historial/Ajustes, con capturas nativas (Qt offscreen puede no mostrar tipografías correctamente).
- Nunca ejecutar muestras reales, subir archivos o modificar sistema para hacer capturas de demostración.

## Orden recomendado
1. **P0 confiabilidad:** EXE contiene esquema SQLite y pruebas de arranque; descarga de binario verificable.
2. **P1 interfaz:** transparencia, sidebar y flujo de fallo legible; cobertura y estado reales. Esta rama incluye estos cambios.
3. **P2 investigación:** modelo de datos de timeline y visualización de evidencias (requiere nuevas fuentes/eventos reales).
4. **P3 rendimiento:** perfiles, throttling, cola y duraciones por motor, costos controlados.
5. **P4 seguridad:** revisión ACL, aislamiento de parsers, pruebas de cuarentena en Windows VM antes de distribuir mitigación.

## Límites
Todas las referencias son proyectos externos; la licencia de cada recurso debe examinarse antes de reutilizar código, diseños, iconos o imágenes. Solo se proponen patrones generales y una implementación propia.
