import re

from core.hips_logger import log_alarma


HERRAMIENTAS_SNIFFER = {
    "tcpdump",
    "wireshark",
    "tshark",
    "ethereal",
    "dumpcap",
}

WRAPPERS_A_IGNORAR = {
    "sudo",
    "timeout",
    "grep",
}


def _es_linea_cabecera(linea: str) -> bool:
    return linea.lower().strip().startswith(("pid ", "user ", "uid "))


def _normalizar_token(token: str) -> str:
    token = token.strip().strip('"').strip("'")
    token = token.split("/")[-1]
    return token.lower()


def _extraer_pid(linea: str):
    partes = linea.strip().split()

    for parte in partes:
        if parte.isdigit():
            return parte

    return None


def _detectar_herramienta(linea: str):
    partes = linea.strip().split()

    if not partes:
        return None

    if "grep" in [_normalizar_token(p) for p in partes]:
        return None

    for indice, parte in enumerate(partes):
        token = _normalizar_token(parte)

        if token not in HERRAMIENTAS_SNIFFER:
            continue

        anteriores = {_normalizar_token(p) for p in partes[:indice]}

        if anteriores.intersection(WRAPPERS_A_IGNORAR):
            return None

        return token

    return None


def analizar_procesos_sniffers(procesos_texto: str, registrar_alertas: bool = True) -> list[dict]:
    alertas = []

    for linea in procesos_texto.splitlines():
        if not linea.strip() or _es_linea_cabecera(linea):
            continue

        herramienta = _detectar_herramienta(linea)

        if not herramienta:
            continue

        pid = _extraer_pid(linea)

        alerta = {
            "tipo": "sniffer_detectado",
            "severidad": "alta",
            "pid": pid,
            "herramienta": herramienta,
            "proceso": herramienta,
            "linea": linea.strip(),
            "detalle": f"Se detectó posible sniffer activo: {herramienta}",
        }

        alertas.append(alerta)

        if registrar_alertas:
            log_alarma(
                modulo="sniffers",
                severidad="alta",
                evento="sniffer_detectado",
                detalle=alerta["detalle"],
                extra={
                    "pid": pid,
                    "herramienta": herramienta,
                    "proceso": herramienta,
                    "linea": linea.strip(),
                }
            )

    return alertas


def detectar_sniffers_en_texto(procesos_texto: str) -> list[dict]:
    return analizar_procesos_sniffers(
        procesos_texto,
        registrar_alertas=False
    )


def analizar_interfaces_promiscuas(
    ip_link_texto: str,
    registrar_alertas: bool = True,
    interfaces_permitidas=None
) -> list[dict]:
    alertas = []
    interfaz_actual = None
    interfaces_permitidas = set(interfaces_permitidas or [])

    for linea in ip_link_texto.splitlines():
        match_interfaz = re.match(r"^\d+:\s+([^:]+):", linea)
        if match_interfaz:
            interfaz_actual = match_interfaz.group(1).split("@")[0]

        if "PROMISC" not in linea:
            continue

        interfaz = interfaz_actual or "desconocida"

        if interfaz in interfaces_permitidas:
            continue

        alerta = {
            "tipo": "interfaz_promiscua",
            "severidad": "alta",
            "interfaz": interfaz,
            "linea": linea.strip(),
            "detalle": f"Interfaz en modo promiscuo detectada: {interfaz}",
        }

        alertas.append(alerta)

        if registrar_alertas:
            log_alarma(
                modulo="sniffers",
                severidad="alta",
                evento="interfaz_promiscua",
                detalle=alerta["detalle"],
                extra={
                    "interfaz": interfaz,
                    "linea": linea.strip(),
                }
            )

    return alertas


def detectar_interfaces_promiscuas(salida_ip_link=None):
    import re
    import subprocess

    if salida_ip_link is None:
        try:
            proceso = subprocess.run(
                ["ip", "link", "show"],
                text=True,
                capture_output=True,
                timeout=5
            )
            salida_ip_link = proceso.stdout
        except Exception:
            salida_ip_link = ""

    alertas = []
    patron = re.compile(r"^\d+:\s+([^:]+):\s+<([^>]*)>")

    for linea in (salida_ip_link or "").splitlines():
        m = patron.search(linea.strip())
        if not m:
            continue

        interfaz = m.group(1).split("@")[0]
        flags = [x.strip().upper() for x in m.group(2).split(",")]

        if "PROMISC" in flags:
            alertas.append({
                "tipo": "interfaz_promiscua",
                "interfaz": interfaz,
                "severidad": "alta",
                "detalle": f"Interfaz en modo promiscuo: {interfaz}",
                "descripcion": f"Interfaz en modo promiscuo: {interfaz}",
            })

    return alertas

# HIPS_PROMISC_COMPAT_FINAL
def detectar_interfaces_promiscuas(salida_ip_link=None, interfaces_permitidas=None):
    import re
    import subprocess

    if interfaces_permitidas is None:
        interfaces_permitidas = set()

    if salida_ip_link is None:
        try:
            proceso = subprocess.run(
                ["ip", "link", "show"],
                text=True,
                capture_output=True,
                timeout=5
            )
            salida_ip_link = proceso.stdout
        except Exception:
            salida_ip_link = ""

    alertas = []
    patron = re.compile(r"^\d+:\s+([^:]+):\s+<([^>]*)>")

    for linea in (salida_ip_link or "").splitlines():
        m = patron.search(linea.strip())
        if not m:
            continue

        interfaz = m.group(1).split("@")[0]
        flags = {x.strip().upper() for x in m.group(2).split(",")}

        if interfaz in interfaces_permitidas:
            continue

        if "PROMISC" in flags:
            alertas.append({
                "tipo": "interfaz_promiscua",
                "interfaz": interfaz,
                "severidad": "alta",
                "detalle": f"Interfaz en modo promiscuo: {interfaz}",
                "descripcion": f"Interfaz en modo promiscuo: {interfaz}",
            })

    return alertas
