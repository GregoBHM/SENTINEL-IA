# Etapa 3/5 — PowerShell y scripts codificados, incremento inicial

## Alcance implementado

- La detección estática de scripts reconoce también texto UTF-16LE, habitual
  en PowerShell de Windows, con y sin BOM.
- Extrae **hasta cuatro** argumentos `-EncodedCommand` o `-enc`
  de comandos `powershell.exe` / `pwsh` encontrados en la primera
  porción acotada del script. Decodifica Base64 como UTF-16LE en memoria,
  sin ejecutar comandos, invocar intérpretes ni consultar la red.
- La búsqueda de indicadores solo se realiza en las cadenas leídas
  (no hay desofuscación recursiva, sandbox, ejecución ni emulación).
- Los hallazgos requieren al menos dos categorías de indicadores.
  El mero uso de `-EncodedCommand` **no produce una alerta de malware**.
- Las categorías y límites se reutilizan para scripts dentro de archivos
  comprimidos; las muestras que superan el presupuesto producen omisión.
- El contenido de los comandos decodificados no se incluye en razones,
  evidencias ni telemetría de GUI.

## Limitaciones

- Indicadores heurísticos no prueban infección, exfiltración o persistencia.
  Un script legítimo puede utilizar esas mismas funciones.
- Solo una pequeña porción de los formatos de ofuscación de PowerShell
  queda cubierta: no se detectan todas las variantes de IEX, AMSI bypass,
  strings concatenadas, compresión, encoding alternativo o scripts remotos.
- Bloques codificados malformados, gigantes o anidados no se descifran.
  No interpretar ausencia de indicadores como contenido limpio.
- El análisis de 7z continúa con contenido no inspeccionado en el módulo
  existente; requiere worker aislado antes de habilitar descompresión.

## QA

```powershell
python -m pytest -q tests/test_powershell_encoded_static_v2.py
python -m pytest -q
```

Validar compatibilidad con reglas YARA, archivo ZIP, UTF-16, memoria y falso
positivo con scripts benignos; después, Windows CI y pruebas en una VM.
No habilitar mitigación automática a partir de estas señales.
