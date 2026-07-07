import re

from core.hips_logger import log_alarma


PATRONES_SOSPECHOSOS = [
    {
        "tipo": "correo_diferido",
        "patron": re.compile(r"deferred|deferido", re.IGNORECASE),
        "detalle": "Se detectaron correos diferidos en la cola",
    },
    {
        "tipo": "error_conexion_correo",
        "patron": re.compile(r"connection timed out|connection refused|no route to host", re.IGNORECASE),
        "detalle": "Se detectaron errores de conexión en la cola de correo",
    },
    {
        "tipo": "rebote_correo",
        "patron": re.compile(r"mailer-daemon|postmaster|user unknown|host unknown", re.IGNORECASE),
        "detalle": "Se detectaron rebotes o destinatarios inválidos",
    },
    {
        "tipo": "posible_spam_correo",
        "patron": re.compile(r"spam|blacklist|blocked", re.IGNORECASE),
        "detalle": "Se detectaron indicios de spam o bloqueo",
    },
]


def cola_esta_vacia(salida_mailq: str) -> bool:
    return "mail queue is empty" in salida_mailq.lower() or "cola de correo vacía" in salida_mailq.lower()


def contar_mensajes_cola(salida_mailq: str) -> int:
    if cola_esta_vacia(salida_mailq):
        return 0

    cantidad = 0

    for linea in salida_mailq.splitlines():
        limpia = linea.strip()

        if not limpia:
            continue

        if limpia.lower().startswith("total requests:"):
            partes = limpia.split(":")
            if len(partes) == 2:
                try:
                    return int(partes[1].strip())
                except ValueError:
                    pass

        if re.match(r"^[A-F0-9]{5,}\*?\s+", limpia, re.IGNORECASE):
            cantidad += 1

    return cantidad


def analizar_cola_correo(salida_mailq: str, umbral_cola: int = 20, registrar_alertas: bool = True) -> list[dict]:
    alertas = []
    cantidad = contar_mensajes_cola(salida_mailq)

    if cantidad >= umbral_cola:
        alertas.append({
            "tipo": "cola_correo_alta",
            "severidad": "alta",
            "detalle": f"La cola de correo tiene {cantidad} mensajes pendientes",
            "cantidad": cantidad,
        })

    for regla in PATRONES_SOSPECHOSOS:
        if regla["patron"].search(salida_mailq):
            alertas.append({
                "tipo": regla["tipo"],
                "severidad": "media",
                "detalle": regla["detalle"],
                "cantidad": cantidad,
            })

    if registrar_alertas:
        for alerta in alertas:
            log_alarma(
                modulo="mail_queue",
                severidad=alerta["severidad"],
                evento=alerta["tipo"],
                detalle=alerta["detalle"],
                extra={
                    "cantidad": alerta["cantidad"],
                    "tipo": alerta["tipo"],
                }
            )

    return alertas
