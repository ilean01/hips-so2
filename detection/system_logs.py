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


PATRONES_HTTP_SOSPECHOSOS = [
    re.compile(r"\.\./", re.IGNORECASE),
    re.compile(r"/etc/passwd", re.IGNORECASE),
    re.compile(r"\.env", re.IGNORECASE),
    re.compile(r"\.git", re.IGNORECASE),
    re.compile(r"wp-admin|wp-login", re.IGNORECASE),
    re.compile(r"union\s+select|select.+from", re.IGNORECASE),
    re.compile(r"sqlmap|nikto|masscan", re.IGNORECASE),
]


def extraer_ip_http(linea: str):
    coincidencia_inicio = re.match(r"^\s*((?:\d{1,3}\.){3}\d{1,3})\s+", linea)
    if coincidencia_inicio:
        return coincidencia_inicio.group(1)

    coincidencia_cliente = re.search(r"\bclient\s+((?:\d{1,3}\.){3}\d{1,3})\b", linea, re.IGNORECASE)
    if coincidencia_cliente:
        return coincidencia_cliente.group(1)

    coincidencia = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", linea)
    if coincidencia:
        return coincidencia.group(0)

    return None


def es_linea_http(linea: str) -> bool:
    return bool(
        re.search(r'"(?:GET|POST|HEAD|PUT|DELETE|OPTIONS)\s+', linea)
        or "http/" in linea.lower()
        or "access_log" in linea.lower()
        or "access.log" in linea.lower()
    )


def es_http_404(linea: str) -> bool:
    if not es_linea_http(linea):
        return False

    return bool(
        re.search(r'"\s+404\s', linea)
        or re.search(r"\s404\s", linea)
    )


def tiene_patron_http_sospechoso(linea: str) -> bool:
    if not es_linea_http(linea):
        return False

    return any(patron.search(linea) for patron in PATRONES_HTTP_SOSPECHOSOS)


def analizar_linea_log(linea: str):
    for regla in PATRONES_LOGS:
        if regla["patron"].search(linea):
            return {
                "tipo": regla["evento"],
                "severidad": regla["severidad"],
                "detalle": regla["descripcion"],
                "linea": linea.strip(),
            }

    if tiene_patron_http_sospechoso(linea):
        ip = extraer_ip_http(linea) or "sin_ip"
        return {
            "tipo": "scanner_http",
            "severidad": "alta",
            "ip": ip,
            "detalle": f"Se detectó patrón sospechoso de scanner HTTP desde {ip}",
            "linea": linea.strip(),
        }

    return None


def analizar_logs_sistema(
    contenido_logs: str,
    registrar_alertas: bool = True,
    umbral_http_404: int = 20,
) -> list[dict]:
    alertas = []
    errores_404_por_ip = {}

    for linea in contenido_logs.splitlines():
        if es_http_404(linea):
            ip = extraer_ip_http(linea) or "sin_ip"
            errores_404_por_ip[ip] = errores_404_por_ip.get(ip, 0) + 1

        alerta = analizar_linea_log(linea)

        if alerta is None:
            continue

        alertas.append(alerta)

        if registrar_alertas:
            extra = {
                "linea": alerta["linea"],
            }
            if alerta.get("ip"):
                extra["ip"] = alerta["ip"]

            log_alarma(
                modulo="system_logs",
                severidad=alerta["severidad"],
                evento=alerta["tipo"],
                detalle=alerta["detalle"],
                extra=extra
            )

    for ip, cantidad in errores_404_por_ip.items():
        if ip != "sin_ip" and cantidad >= umbral_http_404:
            alerta = {
                "tipo": "scanner_http",
                "severidad": "alta",
                "ip": ip,
                "cantidad_404": cantidad,
                "detalle": f"Se detectaron {cantidad} errores HTTP 404 desde la IP {ip}",
            }
            alertas.append(alerta)

            if registrar_alertas:
                log_alarma(
                    modulo="system_logs",
                    severidad=alerta["severidad"],
                    evento=alerta["tipo"],
                    detalle=alerta["detalle"],
                    extra={
                        "ip": ip,
                        "cantidad_404": cantidad,
                        "umbral_http_404": umbral_http_404
                    }
                )

    return alertas
