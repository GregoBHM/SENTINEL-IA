# Modelo de seguridad — prototipo Fase 3

- **Regla absoluta de esta fase:** ninguna modificación del equipo. Solo lectura. Sin borrado, desactivación de Defender, cambios en ACL/registro/tareas, ejecución de muestras o conexión a destinos de un archivo sospechoso.
- **Privacidad:** hashes SHA-256 enviados solo tras `--online` y claves configuradas por entorno. Los nombres de cuenta, credenciales, cookies, rutas y contenidos nunca se envían a la reputación remota. Las conexiones de red solo se cuentan por proceso anómalo, sin guardar destinos.
- **Arquivos comprimidos:** no se escriben miembros extraídos al disco. Hay límites conservadores de input/bytes/entradas/anidamiento, pero faltan procesos aislados para contener fallos o bloqueos del parser. 7z permanece como inventario marcado incompleto. RAR puede depender de un programa externo, por lo que NO se garantiza un sandbox.
- **PE/Authenticode:** `WinVerifyTrust` para resultados `valid`, `unsigned`, `invalid_or_untrusted`, `unavailable`. Una firma `valid` no verifica que el editor sea Microsoft ni la ausencia de malware. Revocación online no consultada.
- **Whitelisting:** no declarar seguro un objeto por su nombre/ruta. Una excepción hash existente solo suprime el veredicto en la interfaz futura; la evidencia se conserva.
- **Falsos positivos:** clave Run, puerto, PowerShell, importación o alta entropía aislados no bastan para clasificación grave.
- **Falsos negativos:** sin memoria histórica, no se puede certificar ausencia de stealer, C2 o rootkit. El análisis de archivos inaccesibles es parcial.
- **Recomendación de respuesta:** ante compromiso real, recoger evidencia, usar Windows confiable para recuperación de cuentas, aislar equipo según criticidad y considerar reinstalación si se pierde confianza en el sistema. Fase 5 añadirá respuesta confirmada y reversible.
