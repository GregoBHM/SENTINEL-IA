# Sentinel OneGuard 2.0 — Fase 3D.4, incremento 1

## Problema

Antes de esta fase, cada archivo candidato PE podía leerse completo una vez
para su observación de identidad SHA-256 y otra para las firmas locales
SHA-256/MD5 del `HashEngine`. La comprobación de allowlist hacía otra
invocación del hash engine (normalmente cacheada).

## Cambio

1. `observe_file_identity` calcula SHA-256 y MD5 sobre **los mismos bloques**
   durante su lectura acotada. MD5 se usa solo por compatibilidad con
   `FileHashes`, nunca como autenticación ni evidencia de seguridad.
2. El resultado de solo lectura retiene una huella de metadatos temporal
   (`dev`, `ino`, longitud, `mtime_ns`, `ctime_ns`) para el mismo scan.
3. `HashEngine.scan_with_hashes` evalúa firmas sin volver a leer el archivo;
   `HashEngine.scan` conserva el contrato de hashing normal.
4. `ScannerManager` solo reutiliza el digest si la identidad fue observada
   y la huella actual de la ruta sigue coincidiendo. Si no, usa
   `compute_hashes` con comprobación de cambios.
5. La comprobación posterior a los motores invalida una identidad desfasada,
   registra una omisión de cobertura y evita persistir ese digest como
   evidencia actual. Las detecciones y los cambios automáticos permanecen
   separados de la identidad.

## Límites y riesgos

- La huella de metadatos reduce inconsistencias ordinarias, pero **no es
  garantía criptográfica ni protege frente a todo TOCTOU** (renombrados,
  hardlinks, escritores maliciosos que restauran metadata, reparse points en
  directorios padres). La ruta no se mantiene abierta durante todos los
  motores. No debe autorizar cuarentena ni declarar el dispositivo limpio.
- Un SHA-256 de un fichero en disco no demuestra que se corresponda con la
  imagen previamente cargada por un proceso.
- La reutilización se limita a una observación **de esta sesión de escaneo**;
  no se introduce un caché global nuevo ni reconocimiento por ruta solamente.
- Archivos que exceden el límite de observación siguen pasando por el
  HashEngine existente. Se registra cobertura parcial del observador sin
  modificar los detectores anteriores.
- Es posible una lectura breve adicional para el encabezado y otras lecturas
  por YARA, PE, scripts y motores independientes. Esta etapa optimiza
  exclusivamente el doble hashing de identidad y firmas.
- La comprobación de cambios entre las fases depende de metadatos; una
  mutación no detectable aún puede dejar un resultado antiguo.
- Un hash detectado sigue siendo evidencia del contenido leído en cierto
  instante, no prueba la familia, origen o persistencia de una infección.

## Aceptación

```powershell
python -m pytest -q tests/test_file_identity_v2.py tests/test_file_identity_integration_v2.py tests/test_hash_single_pass_3d4.py
python -m pytest -q
```

GitHub Actions Windows debe volver a compilar PyInstaller y verificar recursos
antes de integrar. Medir en una VM con fixtures sintéticos de tamaños variados,
sin muestras reales ni datos sensibles, comparando lecturas de disco y tiempo
mediano con una versión de base comparable.

## Próximo incremento

- Benchmark determinista de lecturas por target, y presupuesto de I/O agregado.
- Analizar si el caché existente se puede aprovechar sin aceptar hashes
  obsoletos; requerirá un modelo más fuerte de estado de archivo.
- Optimizar contención entre workers solo después de pruebas Windows.
