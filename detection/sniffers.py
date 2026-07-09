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



INTERFACES_PROMISCUAS_PERMITIDAS = {
    "lo",
    "docker0",
    "virbr0",
}


def detectar_interfaces_promiscuas(salida_ip_link: str, interfaces_permitidas=None) -> list[dict]:
    if interfaces_permitidas is None:
        interfaces_permitidas = INTERFACES_PROMISCUAS_PERMITIDAS

    interfaces_permitidas = set(interfaces_permitidas)
    alertas = []

    for linea in salida_ip_link.splitlines():
        linea_limpia = linea.strip()

        if not linea_limpia:
            continue

        partes = linea_limpia.split(":", 2)

        if len(partes) < 3 or not partes[0].strip().isdigit():
            continue

        interfaz = partes[1].strip().split("@")[0]
        resto = partes[2]

        if "<" not in resto or ">" not in resto:
            continue

        flags = resto.split("<", 1)[1].split(">", 1)[0].split(",")
        flags = {flag.strip().upper() for flag in flags}

        if "PROMISC" in flags and interfaz not in interfaces_permitidas:
            alertas.append({
                "tipo": "interfaz_promiscua",
                "interfaz": interfaz,
                "detalle": f"Interfaz en modo promiscuo detectada: {interfaz}",
                "linea": linea_limpia,
            })

    return alertas


def analizar_interfaces_promiscuas(
    salida_ip_link: str,
    interfaces_permitidas=None,
    registrar_alertas: bool = True
) -> list[dict]:
    alertas = detectar_interfaces_promiscuas(
        salida_ip_link,
        interfaces_permitidas=interfaces_permitidas
    )

    if registrar_alertas:
        for alerta in alertas:
            log_alarma(
                modulo="sniffers",
                severidad="alta",
                evento=alerta["tipo"],
                detalle=alerta["detalle"],
                extra={
                    "interfaz": alerta["interfaz"],
                    "linea": alerta["linea"],
                }
            )

    return alertas
