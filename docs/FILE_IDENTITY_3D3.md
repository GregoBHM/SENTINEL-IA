# Sentinel OneGuard 2.0 — 3D.3 (primer incremento)

## Estado
Módulo de observación de contenido agregado sin conectar todavía al pipeline
de escaneo, a SQLite ni al motor de decisiones. No modifica clasificaciones,
firmas, mitigación ni interfaz. Esta fase no está completa.

## Contrato de `observe_file_identity`
- Entrada: ruta y límites de bytes, tiempo y tamaño de chunk.
- Salida: `FileIdentity` inmutable con estado, SHA-256 opcional, tamaño,
  bytes leídos, tiempo y explicación.
- `observed`: se leyó un archivo regular y la metadata del descriptor y
  la ruta era coherente antes y después. **No indica seguridad**.
- `limited`: límite de bytes o tiempo; nunca entrega hash parcial.
- `changed`: cambios observables de identidad, longitud o metadata.
- `unsupported`: directorio o enlace simbólico.
- `unavailable`: lectura imposible.
- Los archivos grandes quedan fuera del presupuesto; no generan hallazgos
  de malware por el solo hecho de ser grandes.

## Riesgos conocidos
- La comprobación de metadatos no bloquea escrituras concurrentes ni resuelve
  todos los ataques TOCTOU. No representa una instantánea atómica.
- En Windows, los puntos de reanálisis distintos de symlinks requieren
  comprobación explícita mediante APIs Win32 antes de confiar en los datos.
- Un hash en disco no prueba que esos bytes sean los cargados por un proceso.
- No se realiza validación Authenticode en este módulo.
- El límite de tiempo se comprueba entre lecturas: una sola lectura de disco
  bloqueada puede superar el presupuesto.
- Nunca se debe usar esta evidencia como única autorización para cuarentena.

## Próximos incrementos
1. Validar en CI Linux y Windows, incluidos enlaces, reparse points, cambios
   concurrentes y permisos.
2. Introducir un recolector separado y un presupuesto global de I/O.
3. Persistir evidencia y estados de cobertura en SQLite con migraciones aditivas.
4. Asociar observaciones con el PID+create_time solo con procedencia y sin
   afirmar identidad de la imagen mapeada.
5. Integrar firma Authenticode y vista UI después de pruebas nativas.
