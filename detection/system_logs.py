import re

from core.hips_logger import log_alarma


PATRONES_LOGS = [
    {
        "evento": "segfault_detectado",
        "severidad": "alta",
        "patron": re.compile(r"segfault", re.IGNORECASE),
        "descripcion": "Se detectó un error de segmentación en logs del sistema",
    },
    {
        "evento": "oom_detectado",
        "severidad": "alta",
        "patron": re.compile(r"out of memory|oom-killer|killed process", re.IGNORECASE),
        "descripcion": "Se detectó posible falta de memoria u OOM killer",
    },
    {
        "evento": "servicio_fallido",
        "severidad": "media",
        "patron": re.compile(r"failed to start|failed with result|unit .* failed", re.IGNORECASE),
        "descripcion": "Se detectó un servicio fallido",
    },
    {
        "evento": "selinux_denied",
        "severidad": "alta",
        "patron": re.compile(r"avc[:\s]+denied|selinux.*denied", re.IGNORECASE),
        "descripcion": "Se detectó una denegación de SELinux",
    },
    {
        "evento": "permiso_denegado",
        "severidad": "media",
        "patron": re.compile(r"permission denied|permiso denegado", re.IGNORECASE),
        "descripcion": "Se detectó un permiso denegado",
    },
    {
        "evento": "sudo_fallido",
        "severidad": "alta",
        "patron": re.compile(r"sudo.*authentication failure|incorrect password attempt", re.IGNORECASE),
        "descripcion": "Se detectó un intento fallido de sudo",
    },
]


def analizar_linea_log(linea: str):
    for regla in PATRONES_LOGS:
        if regla["patron"].search(linea):
            return {
                "tipo": regla["evento"],
                "severidad": regla["severidad"],
                "detalle": regla["descripcion"],
                "linea": linea.strip(),
            }

    return None


def analizar_logs_sistema(contenido_logs: str, registrar_alertas: bool = True) -> list[dict]:
    alertas = []

    for linea in contenido_logs.splitlines():
        alerta = analizar_linea_log(linea)

        if alerta is None:
            continue

        alertas.append(alerta)

        if registrar_alertas:
            log_alarma(
                modulo="system_logs",
                severidad=alerta["severidad"],
                evento=alerta["tipo"],
                detalle=alerta["detalle"],
                extra={
                    "linea": alerta["linea"],
                }
            )

    return alertas
