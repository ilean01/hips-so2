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


def detectar_sniffers_en_texto(salida_procesos: str) -> list[dict]:
    alertas = []

    for linea in salida_procesos.splitlines():
        linea_limpia = linea.strip()
        linea_lower = linea_limpia.lower()

        for sniffer in SNIFFERS_SOSPECHOSOS:
            if sniffer in linea_lower:
                alertas.append({
                    "tipo": "sniffer_detectado",
                    "herramienta": sniffer,
                    "detalle": f"Se detectó posible sniffer activo: {sniffer}",
                    "proceso": linea_limpia
                })
                break

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
                    "proceso": alerta["proceso"]
                }
            )

    return alertas
