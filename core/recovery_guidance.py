"""Evidence-sensitive recommendations; never pronounce a host clean."""
from __future__ import annotations


def guidance_for(threat_type: str, severity: str, *, is_partial: bool = False) -> list[str]:
    """Return safe manual steps without claiming origin, attribution or exfiltration."""
    category = threat_type.casefold()
    result = [
        "Conserva el informe y verifica el origen, firma y evidencia del hallazgo.",
        "Corrobora el resultado con Microsoft Defender y revisa las detecciones adicionales.",
    ]
    if any(key in category for key in ("stealer", "credencial", "cookie", "token", "sesión")):
        result.append("Desde otro dispositivo confiable, revoca sesiones y cambia contraseñas; habilita MFA.")
        result.append("La retirada del malware no revoca automáticamente datos que ya hayan salido del equipo.")
    elif any(key in category for key in ("ransom", "cifrad")):
        result.append("Aísla el equipo de redes y unidades compartidas; conserva copias de seguridad desconectadas.")
    elif any(key in category for key in ("persistencia", "servicio", "tarea")):
        result.append("Revisa el ejecutable asociado, la tarea o el autorun antes de deshabilitarlo.")
    elif any(key in category for key in ("script", "powershell", "descarg")):
        result.append("Comprueba procesos secundarios, tareas programadas y posibles cargas adicionales.")
    if severity in {"critical", "high"}:
        result.append("Si hay indicios de compromiso activo, desconecta temporalmente la red antes de reparar.")
    if is_partial:
        result.append("Cobertura incompleta: no es posible concluir que el sistema esté limpio.")
    result.append("Después de mitigar, realiza un escaneo nuevo y revisa si reaparecen indicadores.")
    result.append("Si se sospecha manipulación del sistema o rootkit, considera reinstalación desde medio confiable.")
    return result
