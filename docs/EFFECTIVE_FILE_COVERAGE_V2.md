# Sentinel OneGuard 2.0 — Etapa 3A: cobertura verificable por motor y archivo

## Problema

Una llamada `engine.scan(target) == []` no basta para afirmar que un motor examinó el objetivo. Los motores de formato limitado devolvían una lista vacía si el archivo o el tipo de objetivo no les correspondía, pero esas llamadas se registraban como comprobaciones completas.

## Contrato actualizado

Cada motor implementa `applies_to(target, file_header)` para decidir si puede analizar esa clase de objetivo. Las integraciones antiguas heredan `True` por compatibilidad, **no** como certificación de cobertura: necesitan su propia revisión para garantizar que distinguen objetivos no aplicables.

- **success:** el motor finalizó su llamada sin excepción. **No implica que el archivo sea seguro, ni que haya consumido todos los bytes.**
- **skipped:** una comprobación aplicable fue omitida por un límite, fallo previsto o política de recursos. Sigue siendo cobertura parcial.
- **error:** la comprobación o su decisión de aplicabilidad falló de forma inesperada.
- **not_applicable:** el objetivo no corresponde al tipo o formato del motor. **No** incrementa omisiones, errores ni comprobaciones finalizadas.
- **not_run:** se canceló el análisis antes de que ese motor pudiera empezar.

Los motores que inspeccionan **archivos arbitrarios** incluyen Hash y YARA (si YARA pudo cargarse). El motor PE mira la cabecera `MZ` para detectar ejecutables renombrados; las extensiones `.exe` sin `MZ` no cuentan como PE analizados. Los motores Script y Archive siguen rutas por extensiones compatibles, que no prueban ausencia de contenido renombrado: YARA puede ayudar con este caso, pero no garantiza cobertura completa. Los motores Process y Persistence solo reciben los objetos Windows de sus inventarios autorizados.

## Persistencia y consultas

`scan_target_engines` registra los estados de cada motor por ruta y sesión, duración, bytes nominales de entrada, señales y motivo. Todo queda en **SQLite local**. La escritura de un objetivo y sus estados se agrupa en una transacción para limitar la sobrecarga.

`scan_engine_metrics` añade las columnas `not_applicable` y `not_run` con migración aditiva. El campo `checks` solo cuenta motores *invocados*; `completed` significa finalizado, no «sin amenazas». Las duraciones solapadas de motores concurrentes no representan el tiempo total de pared.

La interfaz ofrece «Por archivo» durante el análisis y «Cobertura por archivo» en Historial para la sesión seleccionada, con rutas recientes limitadas, búsqueda por ruta exacta y resultados. Ninguna de estas vistas ejecuta un análisis adicional ni envía información a Internet.

## Límites y decisiones pendientes

- Las detecciones de contenido de miembros de comprimidos se documentan mediante evidencias propias del motor Archive. **Aún no existe un inventario de estados por cada miembro interno.** Será una subfase de cobertura de archivos anidados.
- El análisis estático PE sigue sujeto a `pefile`, límite de tamaño y compatibilidad de Authenticode. No ejecuta los objetivos.
- La clasificación de formato de scripts y comprimidos todavía usa extensiones. Mejoras posteriores: clasificación por cabecera, contenidos contenedores, política de detección de polyglots y rutas engañosas.
- Abrir el prefijo de archivo en cada objetivo añade una lectura muy pequeña, pero puede afectar IOPS en lotes de archivos diminutos. **Requiere benchmarks antes/después** antes de afirmar ninguna aceleración.
- Las métricas para sesiones históricas sin tabla por archivo mostrarán que esa evidencia todavía no está disponible: no reconstruyen falsamente datos.
- No hay detección certificada de rootkits, protección en tiempo real ni cuarentena automática. Mantener Microsoft Defender activado.

## Validación

Se requieren: pruebas de aplicabilidad, procesado real con objetivos sintéticos, ausencia de falsos contadores de omisión, cancelación/errores, migración sin pérdida, PySide6 en Windows y empaquetado PyInstaller con `db/schema.sql`.

## Etapa 3B recomendada

Con la cobertura real visible, medir antes/después y evaluar **YARA-X** como backend alternativo optativo. Revisar licencias, compatibilidad de reglas, resultados falsos positivos/negativos y estabilidad en archivos grandes. Comparar contra YARA ya instalado, sin sustituirlo antes de contar con datos. Implementar después rutas de formato y análisis más profundo de miembros de ZIP/7z/RAR. La API Cloud seguirá opcional y no condicionará los motores locales.
