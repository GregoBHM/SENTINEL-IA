# Sentinel OneGuard 2.0 — contrato de mensajes y cobertura (etapa 1)

**Alcance:** cambio compatible con `ScanEvent(kind, payload)`, sin activar servicios en la nube ni modificar la política de mitigación. El código de evento es estable; los títulos y descripciones son representaciones en español para el cliente.

## Capas

1. **Motor / transporte**: `ScanEvent` con `schema_version=1`, `event_id`, `timestamp_utc`, `event_code`, `category`, `level`, `engine`, `path`, `message_params`, `dedupe_key` y `recommended_action`. El campo `message` es un detalle técnico de compatibilidad, no la frase mostrada al cliente.
2. **Presentación**: `core.events.present_event` produce título, descripción, severidad operativa y acción. El texto visible no es una prueba de malware. Un evento antiguo se presenta mediante una regla de compatibilidad.
3. **Persistencia local**: `scan_coverage` registra cada omisión por `(sesión, ruta, motor, código)`. `scan_sessions.omitted_checks` guarda el total independiente de hallazgos y errores. SQLite migra tablas antiguas añadiendo solo la columna necesaria. Las rutas no se sincronizan con la nube.
4. **Interfaz**: el contador «Cobertura parcial» no suma avisos meramente informativos como la ausencia de claves API. Los mensajes repetidos se agrupan en consola y el botón «Ver omisiones» muestra los archivos afectados desde SQLite. Los contadores finales se reconcilian con el resumen del escáner.

## Vocabulario implementado

| Código | Categoría | Ejemplo de mensaje | ¿Amenaza? |
|---|---|---|---|
| `SCAN.REPUTATION.UNCONFIGURED` | information | Reputación en línea no configurada; continúa análisis local | No |
| `SCAN.YARA.SIZE_LIMIT` | coverage | YARA no revisó un archivo grande; mostrar tamaño y límite | No |
| `SCAN.YARA.UNAVAILABLE` | coverage | Motor YARA no disponible | No |
| `SCAN.ENGINE.SKIPPED` | coverage | Un motor omitió un objetivo | No |
| `SCAN.ENGINE.UNAVAILABLE` | coverage | Cobertura parcial del sistema | No |
| `SCAN.ENGINE.ERROR` | error | Un componente no pudo analizar un objetivo | No |

Los hallazgos de malware siguen en el sistema de `Finding` y `AggregatedFinding` — no se mezclan con las omisiones.

## Ejemplo normalizado

```json
{
  "schema_version": 1,
  "event_code": "SCAN.YARA.SIZE_LIMIT",
  "category": "coverage",
  "level": "WARN",
  "engine": "yara",
  "path": "C:/Samples/ejemplo.bin",
  "message_params": {
    "size_bytes": 104857600,
    "limit_bytes": 67108864
  },
  "dedupe_key": "SCAN.YARA.SIZE_LIMIT:yara",
  "recommended_action": "Ver archivos omitidos"
}
```

La cadena en la ruta es ilustrativa; las instancias reales utilizan `event_id` UUID y `timestamp_utc` generado por el motor.

## Límites de esta etapa

- La agrupación visual no altera la base de datos: cada omisión queda consultable.
- Las notificaciones que existían antes de iniciarse una sesión se conservan en consola, pero aún no se asignan a `scan_coverage`, que requiere una sesión.
- El conteo de comprobaciones omitidas no es el de *archivos distintos* y puede superar los objetivos encontrados si más de un motor omite el mismo objetivo.
- El transporte mantiene el límite de cola; el total final del motor es autoritativo para omisiones de archivo. Los avisos de preparación tienen un conteo separado en la UI.
- El texto técnico original no se ejecuta y no se envía a un servicio externo.
- Hay que validar la GUI en Windows interactivo y comprobar que la acción "Ver omisiones" presenta los datos correctamente bajo carga real.

## Etapas siguientes (no implementadas en esta rama)

Instrumentar la disponibilidad y duración de **todos** los motores, ETA por fase con intervalos reales, catálogo completo de errores y detecciones, perfiles de análisis, compresión de eventos de alto volumen y esquema de sincronización optativo y revisado para privacidad.

## Criterios mínimos de prueba

- Las pruebas unitarias validan contrato, idioma, compatibilidad legacy, registros de cobertura y migración SQLite.
- La prueba Qt confirma que el aviso de reputación no incrementa cobertura y tres omisiones YARA se contabilizan aunque en el registro aparezcan agrupadas.
- El workflow de Pull Request en Windows compila un EXE experimental y verifica recursos SQLite y YARA, icono y UAC.
