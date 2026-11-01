# Evidencia de validación local — Fase 3

- **Entorno:** Linux, Python 3.13; no es una validación sobre Windows 10/11.
- **Comando:** `python -m pytest -q`
- **Resultado:** 42 passed, 3 skipped. Las 3 omitidas requieren `yara-python` nativo no instalado.
- Tests: Hash, YARA fake, agregador, reputación simulada sin red, SQLite, eventos, CLI base, pausa/cancelación; más script, ZIP anidado, doble extensión, zip-slip, límites, persistencia de prueba, PID simulado, PE mock, firma no disponible e investigación asociativa.
- **Prueba de flujo real:** CLI `--no-yara --investigate` sobre archivos sintéticos: 2 archivos analizados, hallazgo heurístico de script, nombre engañoso en ZIP, 0 errores registrados y resultado SQLite persistente.
- **Pendiente real:** ejecución Windows, UAC, `WinVerifyTrust` con binarios firmados/no firmados, detección en procesos/servicios/tareas reales, RAR/7z nativo, EICAR, escenarios de límites adversarios y análisis de falsos positivos con corpus benigno. Ninguna tasa de precisión/detección ha sido medida con malware real.
