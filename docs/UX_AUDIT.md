# Auditoría funcional y de experiencia — Sentinel OneGuard

Fecha: 2026-11-01. Revisión estática del código, no certificación antivirus.
Referencia visual aportada: pantalla de análisis de un antivirus comercial. Se toma
como inspiración la claridad de navegación y las opciones de análisis; no se copia
su identidad visual, funcionalidades no implementadas, ni sus iconos.

## 1. Inicio
**Problema previo:** presentación textual de fases, sin elegir el escaneo de inmediato;
estado del equipo poco accionable.
**Aplicado en esta rama:** accesos a Rápido, Completo y Personalizado con asistente
obligatorio; última evaluación basada en SQLite, sin presentar porcentaje de seguridad.
**Pendiente:** instrumentar estado de integridad Windows a partir de fuentes verificadas
antes de ofrecer una tarjeta de «protección».

## 2. Permisos y alcance
**Actual:** tres pasos, lectura autorizada, procesos y persistencia opcionales,
reputación externa opcional, selección de carpetas.
**Pendiente:** mostrar estimación *de alcance* (directorios/volúmenes) antes del inicio,
guardar preferencias no sensibles, indicar claramente los proveedores de API autorizados.
La selección de unidades completas no equivale a análisis de sectores de arranque.

## 3. Análisis en directo y tiempos
**Aplicado:** cronómetro monotónico real, tiempo total/pausa, velocidad observada
(archivos/segundo), trabajo conocido y variable; barras globales indeterminadas
mientras se descubren archivos. Pausa y cancelación siguen siendo cooperativas.
**No hacer:** inventar ETA o completar artificialmente la barra en un fallo.
**Pendiente:** separar latencia/velocidad por motor, colas pendientes y trabajos
bloqueados; instrumentar intervalos de rendimiento y limitar el coste de logs.

## 4. Resultados
**Actual:** tabla con severidad, ruta, familia, motor, motivo y acción; búsqueda,
filtros y detalle de evidencias.
**Aplicado:** reinicio de la tabla al iniciar nueva sesión; resumen de severidades
basado en datos reales, diferenciación visual de avisos informativos y presentación
expresa de límites cuando el resultado está vacío.
**Pendiente:** filtros por motor y estado (omitido, incompleto, excepción),
exportación de vista filtrada e inspección del historial de una misma ruta.

## 5. Investigación
**Actual:** vínculos explicados entre ejecutables y persistencia, con limitaciones.
**Pendiente:** líneas temporales *basadas en timestamps disponibles*, grafo de
relaciones con procedencia y confianza; no atribuir entrada o exfiltración sin registros
observables. No inventar sesiones robadas ni conexiones no registradas.

## 6. Cuarentena / mitigación
**Actual:** confirmaciones, hash, ruta y registro de auditoría; aislamiento,
restauración y HKCU Run limitado.
**Riesgo:** operaciones elevadas basadas en nombres de ruta (TOCTOU), validación
nativa Win32 y ACL aún pendiente. No habilitar acciones destructivas por defecto
en dispositivos reales. Mitigación es experimental.

## 7. Historial
**Aplicado:** duración observada por sesión en pantalla; lectura de sesiones
existentes, con estados completos/cancelados/fallidos.
**Pendiente:** persistir métricas agregadas por fase, duración de pausas y cobertura
para comparaciones longitudinales; diferenciar tasa de detección de tasa de errores.

## 8. Ajustes y privacidad
**Actual:** claves API en memoria, consentimiento explícito, configuración local.
**Pendiente:** interfaz de exclusiones revisables, actualización de reglas firmadas,
versión y licencia de proveedores, acceso a logs, exportación con redactado de rutas
y controles para limpiar información sensible.

## 9. Empaquetado Windows
**Causa confirmada del fallo reportado:** `db/database.py` lee `db/schema.sql`
pero `build.spec` no lo incluía en el bundle one-file de PyInstaller.
**Aplicado:** copiar `db/schema.sql` al destino `db` dentro del paquete;
inicializar SQLite en el smoke test de Qt; prueba estática del manifest;
inspección del CArchive del EXE para comprobar esquema, marca y reglas;
validación Windows por PR. El instalador debe reconstruirse para incorporar el arreglo.
**Pendiente:** validar en runner Windows el `.exe` completo (incluido PyInstaller);
analizar los logs si falla. Los tests en Linux no validan Win32 UAC/ACL.

## 10. Arquitectura de detección
**A preservar:** siete motores independientes, escaneo sin ejecutar muestras,
YARA/PE/hashes y registro de evidencia; el resultado limpio no equivale a
integridad verificada.
**Limitaciones:** firmas YARA sintéticas y base de hashes sin inteligencia real;
RAR condicionado por backend y 7z parcialmente inventariado; sin protección
en tiempo real ni detección fiable de rootkits.
**Prioridades de producción:** aislamiento del parseo de contenidos, telemetría
verificable, pruebas con corpus de benignos, precisión/falsos positivos, políticas
de actualización y revisión de privilegios.

## Criterios de aceptación
- Compilar one-file con logo/UAC en Windows e inicializar SQLite al lanzar un análisis.
- Mostrar tiempo real que se congela al finalizar; nunca un ETA ficticio.
- Una falla de inicialización deja visible el log, sin salto a resultados vacíos.
- Un análisis nuevo no hereda hallazgos anteriores.
- 0 hallazgos muestra explícitamente que no hay garantía de equipo limpio.
- Cualquier mitigación sigue requiriendo confirmación, sin automatización destructiva.

## Notas de diseño
Conservar la paleta oscura original de OneGuard; no clonar la interfaz de otro
antivirus. Priorizar contrastes WCAG, tipografía con jerarquía, navegación con
etiquetas claras y densidad adaptada a 1100x720 y 1920x1080. Animaciones y
efectos solo si comunican estado real; evitar globos, medidores «100% seguro»,
gráficas ficticias y barras de progreso indeterminadas presentadas como exactas.
