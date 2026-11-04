# Sentinel OneGuard 2.0 — Etapa 3D.2: identidad de procesos y referencias de inicio

## Objetivo

Relacionar un proceso observado y una entrada de inicio de Windows **solo cuando la identidad del proceso se haya corroborado y la ruta de ejecutable de la entrada sea inequívoca**. Las coincidencias de ruta no demuestran ejecución, malware, propagación ni causalidad. El sistema continúa siendo local, de solo lectura y sin requisitos de Internet.

## Modelo de observación

El módulo `core/system_identity.py` produce registros `SystemObservation` con estado, motivo y procedencia.

### Proceso

- Se toma la identidad `PID + create_time` del inventario, y se vuelve a consultar usando `psutil.Process(pid)` cuando llega su turno de análisis.
- Si el PID fue reutilizado, el instante no coincide, faltan permisos o no se puede obtener una ruta local absoluta, **no se autoriza una correlación**.
- Una identidad `verified` indica solamente que PID, hora de creación y ruta de ejecutable coincidían en esa instantánea. No demuestra que el proceso aún se esté ejecutando, que el binario no haya cambiado ni que sea seguro.
- La inspección de comportamiento existente sigue separada de la observación de identidad; el análisis no ejecuta el archivo.

### Entrada de inicio

- Se permite una **referencia directa** a un ejecutable local absoluto, incluida una ruta entre comillas con espacios.
- Los comandos ambiguos se excluyen del enlace automático: rutas con variables sin resolver, UNC, caminos relativos, scripts, DLL ejecutadas por hosts, intérpretes como PowerShell/CMD y comandos sin comillas con espacios.
- El resultado `reference_only` significa configuración observada, **no ejecución confirmada**. El motor de persistencia mantiene sus propias heurísticas y puntajes por separado.
- SQLite guarda el SHA-256 del comando de inicio y la entrada/ubicación, **no los argumentos en texto plano**.

## Persistencia y consulta

`scan_system_observations` es una tabla local con las columnas: sesión, identificador de objetivo, tipo, estado, PID, instante de creación, ruta informada, ruta normalizada, fuente de inicio, SHA-256 del comando, nota y hora UTC de observación.

Las escrituras se integran con el estado de los motores en una sola transacción por objetivo. La migración es aditiva mediante `CREATE TABLE IF NOT EXISTS`, conservando las sesiones anteriores.

El informe de relaciones de `core/evidence_trace.py` une exclusivamente:
- Procesos de la **misma sesión** con `status=verified`, PID e instante válidos.
- Entradas de inicio con `status=reference_only`.
- Rutas absolutas de ejecutable normalizadas coincidentes.

La relación se presenta como **«Ruta coincidente con proceso observado»**, acompañada de hora e identificación de la instantánea, con advertencia sobre causalidad.

Los procesos obsoletos o inaccesibles y las entradas de comandos ambiguos aparecen bajo **«Identidad incompleta»** como límites de evidencia, nunca como una detección de malware.

## Mensajes al cliente

- **Verificado en la instantánea:** «Se comprobó PID, hora de creación y ejecutable cuando se analizó el proceso. La observación no es una garantía de seguridad».
- **Referencia de inicio:** «Existe una entrada configurada con una referencia directa a este ejecutable; no confirma que haya lanzado un proceso».
- **Vínculo de ruta:** «Las rutas coinciden. No demuestra que esta entrada iniciara el proceso».
- **PID reutilizado:** «No se pudo verificar la identidad del proceso. Su inspección tiene cobertura parcial».
- **Comando ambiguo:** «El comando contiene un intérprete o una ruta que no permite una asociación automática fiable».

## Límites y decisiones siguientes

1. La correlación por ruta puede fallar con renombrados, hardlinks, alias NTFS y cambios del archivo. No se utiliza como prueba de infección.
2. Una validación fuerte de identidad de contenido requerirá capturar el hash y metadatos del archivo ejecutable de forma coherente, respetando I/O y TOCTOU; **todavía no está implementada**.
3. El historial es de instantáneas: no hay eventos ETW/Sysmon ni línea de tiempo causal que respalde una afirmación sobre cuándo una persistencia inició un proceso.
4. La detección de persistencia conserva sus reglas originales; el módulo de enlace no modifica puntajes ni autoriza respuestas automáticas.
5. Los comandos con variables de entorno, PowerShell, DLL y servicios alojados requieren una fase especializada con normalización y pruebas antes de asociarlos de manera automática.
6. Las consultas están acotadas a una sesión con índices SQLite y límites de resultados. Un registro truncado debe indicarse como tal.
7. Las observaciones permanecen en la base local. Futuros reportes Cloud requerirían consentimiento explícito, minimización de datos y revisión del modelo de acceso.

## Validación de aceptación

- Simular procesos con PID/hora válidos y obsoletos sin consultar procesos reales del usuario.
- Probar referencias directas entrecomilladas, mayúsculas/minúsculas y entradas ambiguas.
- Asegurar que los comandos con intérprete no generan vínculos falsos.
- Verificar privacidad (sin persistir los argumentos originales), aislamiento entre sesiones y SQLite aditivo.
- Comprobar que un PID obsoleto figura como cobertura parcial y que la UI nunca declara una relación causal.
- Validar PySide6, CLI y empaquetado one-file en Windows antes del merge.
