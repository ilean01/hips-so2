import re

from core.hips_logger import log_alarma


PATRONES_SOSPECHOSOS = [
    {
        "tipo": "descarga_remota_cron",
        "patron": re.compile(r"\b(curl|wget)\b.*https?://", re.IGNORECASE),
        "detalle": "Cron descarga contenido remoto con curl o wget",
    },
    {
        "tipo": "reverse_shell_cron",
        "patron": re.compile(r"bash\s+-i|/dev/tcp|nc\s+-e|ncat\s+-e|socat", re.IGNORECASE),
        "detalle": "Cron contiene posible reverse shell",
    },
    {
        "tipo": "ejecucion_tmp_cron",
        "patron": re.compile(r"/tmp/|/var/tmp/", re.IGNORECASE),
        "detalle": "Cron ejecuta o referencia archivos temporales",
    },
    {
        "tipo": "ofuscacion_cron",
        "patron": re.compile(r"base64\s+-d|eval\s+|python\s+-c|perl\s+-e|sh\s+-c", re.IGNORECASE),
        "detalle": "Cron contiene posible comando ofuscado",
    },
    {
        "tipo": "chmod_sospechoso_cron",
        "patron": re.compile(r"chmod\s+\+x|chmod\s+777", re.IGNORECASE),
        "detalle": "Cron cambia permisos de forma sospechosa",
    },
]


def _es_comentario_o_vacio(linea: str) -> bool:
    limpia = linea.strip()
    return not limpia or limpia.startswith("#")


def _es_entrada_cron(linea: str) -> bool:
    partes = linea.split()

    if len(partes) < 6:
        return False

    return True


def _es_cada_minuto(linea: str) -> bool:
    partes = linea.split()

    if len(partes) < 5:
        return False

    return partes[0:5] == ["*", "*", "*", "*", "*"]


def analizar_linea_cron(linea: str) -> list[dict]:
    alertas = []

    if _es_comentario_o_vacio(linea):
        return alertas

    if not _es_entrada_cron(linea):
        return alertas

    linea_limpia = linea.strip()

    if _es_cada_minuto(linea_limpia):
        alertas.append({
            "tipo": "cron_cada_minuto",
            "detalle": "Cron configurado para ejecutarse cada minuto",
            "linea": linea_limpia,
        })

    for regla in PATRONES_SOSPECHOSOS:
        if regla["patron"].search(linea_limpia):
            alertas.append({
                "tipo": regla["tipo"],
                "detalle": regla["detalle"],
                "linea": linea_limpia,
            })

    return alertas


def analizar_crontab(contenido_cron: str, registrar_alertas: bool = True) -> list[dict]:
    alertas = []

    for linea in contenido_cron.splitlines():
        alertas.extend(analizar_linea_cron(linea))

    if registrar_alertas:
        for alerta in alertas:
            severidad = "critica" if alerta["tipo"] == "reverse_shell_cron" else "alta"

            log_alarma(
                modulo="cron_monitor",
                severidad=severidad,
                evento=alerta["tipo"],
                detalle=alerta["detalle"],
                extra={
                    "linea": alerta["linea"],
                    "tipo": alerta["tipo"],
                }
            )

    return alertas
