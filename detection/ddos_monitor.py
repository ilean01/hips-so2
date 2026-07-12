import re

from core.hips_logger import log_alarma


ESTADOS_RELEVANTES = {
    "ESTAB",
    "ESTABLISHED",
    "SYN-RECV",
    "SYN_RECV",
    "SYN_SENT",
    "TIME-WAIT",
    "TIME_WAIT",
}


def extraer_ips(linea: str) -> list:
    return re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", linea)


def extraer_ip_remota(linea: str):
    ips = extraer_ips(linea)

    if not ips:
        return None

    return ips[-1]


def extraer_estado(linea: str) -> str:
    partes = linea.split()

    if not partes:
        return ""

    estado = partes[0].upper()

    if estado in ESTADOS_RELEVANTES:
        return estado

    return ""


def analizar_conexiones_red(
    salida_conexiones: str,
    umbral_conexiones: int = 50,
    umbral_syn: int = 20,
    registrar_alertas: bool = True
) -> list:
    conexiones_por_ip = {}
    syn_por_ip = {}

    for linea in salida_conexiones.splitlines():
        linea = linea.strip()

        if not linea:
            continue

        if linea.lower().startswith("state"):
            continue

        ip_remota = extraer_ip_remota(linea)

        if ip_remota is None:
            continue

        estado = extraer_estado(linea)

        conexiones_por_ip[ip_remota] = conexiones_por_ip.get(ip_remota, 0) + 1

        if estado in {"SYN-RECV", "SYN_RECV", "SYN_SENT"}:
            syn_por_ip[ip_remota] = syn_por_ip.get(ip_remota, 0) + 1

    alertas = []

    for ip, cantidad in conexiones_por_ip.items():
        if cantidad >= umbral_conexiones:
            alertas.append({
                "tipo": "muchas_conexiones_desde_ip",
                "severidad": "alta",
                "ip": ip,
                "cantidad": cantidad,
                "detalle": f"Se detectaron {cantidad} conexiones desde la IP {ip}",
            })

    for ip, cantidad in syn_por_ip.items():
        if cantidad >= umbral_syn:
            alertas.append({
                "tipo": "posible_syn_flood",
                "severidad": "critica",
                "ip": ip,
                "cantidad": cantidad,
                "detalle": f"Se detectaron {cantidad} conexiones SYN desde la IP {ip}",
            })

    if registrar_alertas:
        for alerta in alertas:
            log_alarma(
                modulo="ddos_monitor",
                severidad=alerta["severidad"],
                evento=alerta["tipo"],
                detalle=alerta["detalle"],
                extra={
                    "ip": alerta["ip"],
                    "cantidad": alerta["cantidad"],
                    "tipo": alerta["tipo"],
                }
            )

    return alertas

# HIPS_DNS_QUERY_FLOOD_DETECTOR
def detectar_dns_query_flood(contenido_log_dns: str, umbral_dns: int = 50):
    """
    Detecta posible DDoS a DNS a partir de logs tipo BIND/named.

    Ejemplo de línea:
    12-Jul-2026 14:10:00.001 client 203.0.113.55#53001 (example.com): query: example.com IN A +E
    """
    import re

    contenido_log_dns = contenido_log_dns or ""
    consultas_por_ip = {}

    patron = re.compile(
        r"client\s+(\d{1,3}(?:\.\d{1,3}){3})#\d+.*query:",
        re.IGNORECASE
    )

    for linea in contenido_log_dns.splitlines():
        match = patron.search(linea)
        if not match:
            continue

        ip = match.group(1)
        consultas_por_ip[ip] = consultas_por_ip.get(ip, 0) + 1

    alertas = []

    for ip, cantidad in consultas_por_ip.items():
        if cantidad >= umbral_dns:
            alertas.append({
                "tipo": "dns_query_flood",
                "severidad": "critica",
                "ip": ip,
                "ip_origen": ip,
                "cantidad": cantidad,
                "detalle": f"Se detectaron {cantidad} consultas DNS desde la IP {ip}",
                "descripcion": f"Se detectaron {cantidad} consultas DNS desde la IP {ip}",
            })

    return alertas


def analizar_log_dns_ddos(contenido_log_dns: str, umbral_dns: int = 50):
    """
    Alias legible para usar en documentación y pruebas.
    """
    return detectar_dns_query_flood(contenido_log_dns, umbral_dns=umbral_dns)

# HIPS_DNS_QUERY_FLOOD_DETECTOR
def detectar_dns_query_flood(contenido_log_dns: str, umbral_dns: int = 50):
    """
    Detecta posible DDoS a DNS a partir de logs tipo BIND/named.

    Ejemplo de línea:
    12-Jul-2026 14:10:00.001 client 203.0.113.55#53001 (example.com): query: example.com IN A +E
    """
    import re

    contenido_log_dns = contenido_log_dns or ""
    consultas_por_ip = {}

    patron = re.compile(
        r"client\s+(\d{1,3}(?:\.\d{1,3}){3})#\d+.*query:",
        re.IGNORECASE
    )

    for linea in contenido_log_dns.splitlines():
        match = patron.search(linea)
        if not match:
            continue

        ip = match.group(1)
        consultas_por_ip[ip] = consultas_por_ip.get(ip, 0) + 1

    alertas = []

    for ip, cantidad in consultas_por_ip.items():
        if cantidad >= umbral_dns:
            alertas.append({
                "tipo": "dns_query_flood",
                "severidad": "critica",
                "ip": ip,
                "ip_origen": ip,
                "cantidad": cantidad,
                "detalle": f"Se detectaron {cantidad} consultas DNS desde la IP {ip}",
                "descripcion": f"Se detectaron {cantidad} consultas DNS desde la IP {ip}",
            })

    return alertas


def analizar_log_dns_ddos(contenido_log_dns: str, umbral_dns: int = 50):
    """
    Alias legible para usar en documentación y pruebas.
    """
    return detectar_dns_query_flood(contenido_log_dns, umbral_dns=umbral_dns)
