import re
import pwd

from core.hips_logger import log_alarma


PATRONES_SOSPECHOSOS = [
    {
        "tipo": "correo_diferido",
        "patron": re.compile(r"deferred|deferido|status=deferred", re.IGNORECASE),
        "detalle": "Se detectaron correos diferidos en la cola",
    },
    {
        "tipo": "error_conexion_correo",
        "patron": re.compile(r"connection timed out|connection refused|lost connection|temporary failure|network is unreachable", re.IGNORECASE),
        "detalle": "Se detectaron errores de conexión en el correo",
    },
    {
        "tipo": "rebote_correo",
        "patron": re.compile(r"bounced|bounce|status=bounced|undeliverable|relay access denied|user unknown|recipient address rejected|dsn=5", re.IGNORECASE),
        "detalle": "Se detectaron correos rebotados o rechazados",
    },
]


def cola_esta_vacia(contenido: str) -> bool:
    contenido = contenido or ""
    return "Mail queue is empty" in contenido or "La cola de correo está vacía" in contenido


def contar_mensajes_cola(contenido: str) -> int:
    contenido = contenido or ""

    if cola_esta_vacia(contenido):
        return 0

    match = re.search(r"Total requests:\s*(\d+)", contenido, re.IGNORECASE)
    if match:
        return int(match.group(1))

    ids = re.findall(r"^[A-F0-9]{5,}", contenido, flags=re.MULTILINE)
    return len(ids)


def contar_mensajes_en_cola(contenido: str) -> int:
    return contar_mensajes_cola(contenido)


def analizar_linea_mail_queue(linea: str):
    for regla in PATRONES_SOSPECHOSOS:
        if regla["patron"].search(linea):
            return {
                "tipo": regla["tipo"],
                "severidad": "media",
                "detalle": regla["detalle"],
                "linea": linea.strip(),
            }

    return None


def _extraer_remitente(linea: str):
    match = re.search(r"from=<([^>]+)>", linea, re.IGNORECASE)
    if match:
        return match.group(1).strip().lower()

    return None


def _es_correo_enviado(linea: str) -> bool:
    return bool(re.search(r"status=sent", linea, re.IGNORECASE))


# HIPS_MAIL_QUEUE_USUARIO_GENERADOR
def _usuario_local_desde_remitente(remitente: str):
    if not remitente or "@" not in remitente:
        return None

    usuario = remitente.split("@", 1)[0].strip().lower()

    try:
        pwd.getpwnam(usuario)
        return usuario
    except KeyError:
        return None


def _detectar_envio_masivo(contenido: str, umbral_envio_masivo: int):
    envios_por_remitente = {}

    for linea in contenido.splitlines():
        remitente = _extraer_remitente(linea)

        if not remitente:
            continue

        if not _es_correo_enviado(linea):
            continue

        envios_por_remitente[remitente] = envios_por_remitente.get(remitente, 0) + 1

    alertas = []

    for remitente, cantidad in envios_por_remitente.items():
        if cantidad >= umbral_envio_masivo:
            alerta = {
                "tipo": "envio_masivo_correo",
                "severidad": "alta",
                "remitente": remitente,
                "cantidad": cantidad,
                "detalle": f"Se detectaron {cantidad} envíos de correo desde {remitente}",
            }

            usuario = _usuario_local_desde_remitente(remitente)
            if usuario:
                alerta["usuario"] = usuario
                alerta["detalle"] = f"Se detectaron {cantidad} envíos de correo desde el usuario local {usuario} ({remitente})"

            alertas.append(alerta)

    return alertas


def analizar_cola_correo(
    contenido: str,
    umbral: int = 10,
    registrar_alertas: bool = True,
    umbral_envio_masivo: int = 5,
    umbral_cola=None,
) -> list[dict]:
    if umbral_cola is not None:
        umbral = umbral_cola

    contenido = contenido or ""
    alertas = []

    cantidad_cola = contar_mensajes_cola(contenido)

    if cantidad_cola >= umbral:
        alertas.append({
            "tipo": "cola_correo_alta",
            "severidad": "alta",
            "cantidad": cantidad_cola,
            "detalle": f"La cola de correo contiene {cantidad_cola} mensajes",
        })

    for linea in contenido.splitlines():
        for regla in PATRONES_SOSPECHOSOS:
            if regla["patron"].search(linea):
                alertas.append({
                    "tipo": regla["tipo"],
                    "severidad": "media",
                    "detalle": regla["detalle"],
                    "linea": linea.strip(),
                })

    alertas.extend(
        _detectar_envio_masivo(
            contenido,
            umbral_envio_masivo=umbral_envio_masivo
        )
    )

    if registrar_alertas:
        for alerta in alertas:
            log_alarma(
                modulo="mail_queue",
                severidad=alerta.get("severidad", "media"),
                evento=alerta["tipo"],
                detalle=alerta["detalle"],
                extra=alerta,
            )

    return alertas


def analizar_mail_queue(*args, **kwargs):
    return analizar_cola_correo(*args, **kwargs)
