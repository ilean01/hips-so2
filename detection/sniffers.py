from pathlib import Path

from core.hips_logger import log_alarma


SNIFFERS_SOSPECHOSOS = [
    "tcpdump",
    "wireshark",
    "tshark",
    "dumpcap",
    "ettercap",
    "dsniff",
    "snort",
]


def _parsear_linea_proceso(linea: str):
    linea_limpia = linea.strip()

    if not linea_limpia:
        return None

    partes = linea_limpia.split(None, 5)

    # Formato esperado desde runner:
    # pid user %cpu %mem comm args
    if len(partes) >= 5 and partes[0].isdigit():
        return {
            "pid": partes[0],
            "usuario": partes[1],
            "comando": partes[4],
            "argumentos": partes[5] if len(partes) > 5 else partes[4],
            "linea": linea_limpia,
        }

    # Formato simple para pruebas manuales:
    # tcpdump -i lo
    comando = partes[0]

    return {
        "pid": None,
        "usuario": None,
        "comando": comando,
        "argumentos": linea_limpia,
        "linea": linea_limpia,
    }


def _nombre_comando(comando: str) -> str:
    return Path(comando).name.lower()


def detectar_sniffers_en_texto(salida_procesos: str) -> list[dict]:
    alertas = []

    for linea in salida_procesos.splitlines():
        proceso = _parsear_linea_proceso(linea)

        if proceso is None:
            continue

        comando_base = _nombre_comando(proceso["comando"])

        if comando_base in SNIFFERS_SOSPECHOSOS:
            alertas.append({
                "tipo": "sniffer_detectado",
                "herramienta": comando_base,
                "pid": proceso["pid"],
                "usuario": proceso["usuario"],
                "detalle": f"Se detectó posible sniffer activo: {comando_base}",
                "proceso": proceso["linea"],
            })

    return alertas


def analizar_procesos_sniffers(salida_procesos: str, registrar_alertas: bool = True) -> list[dict]:
    alertas = detectar_sniffers_en_texto(salida_procesos)

    if registrar_alertas:
        for alerta in alertas:
            log_alarma(
                modulo="sniffers",
                severidad="alta",
                evento="sniffer_detectado",
                detalle=alerta["detalle"],
                extra={
                    "herramienta": alerta["herramienta"],
                    "pid": alerta["pid"],
                    "usuario": alerta["usuario"],
                    "proceso": alerta["proceso"],
                }
            )

    return alertas
