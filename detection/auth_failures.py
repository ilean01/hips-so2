from pathlib import Path
import re
from typing import Optional

from core.hips_logger import log_alarma


PATRONES_FALLO = [
    re.compile(r"Failed password", re.IGNORECASE),
    re.compile(r"Invalid user", re.IGNORECASE),
    re.compile(r"authentication failure", re.IGNORECASE),
    re.compile(r"Failed publickey", re.IGNORECASE),
]


def es_intento_fallido(linea: str) -> bool:
    return any(patron.search(linea) for patron in PATRONES_FALLO)


def extraer_ip(linea: str) -> Optional[str]:
    coincidencia = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", linea)
    if coincidencia:
        return coincidencia.group(0)
    return None


def analizar_log_auth(ruta_log: str, umbral: int = 5, registrar_alertas: bool = True) -> list[dict]:
    path = Path(ruta_log)

    if not path.exists():
        raise FileNotFoundError(f"No existe el log de autenticación: {ruta_log}")

    intentos_por_ip = {}

    with open(path, "r", encoding="utf-8", errors="ignore") as archivo:
        for linea in archivo:
            if not es_intento_fallido(linea):
                continue

            ip = extraer_ip(linea) or "sin_ip"
            intentos_por_ip[ip] = intentos_por_ip.get(ip, 0) + 1

    alertas = []

    for ip, cantidad in intentos_por_ip.items():
        if cantidad >= umbral:
            alerta = {
                "tipo": "multiples_intentos_fallidos",
                "ip": ip,
                "cantidad": cantidad,
                "detalle": f"Se detectaron {cantidad} intentos fallidos de autenticación desde {ip}"
            }
            alertas.append(alerta)

            if registrar_alertas:
                log_alarma(
                    modulo="auth_failures",
                    severidad="alta",
                    evento="multiples_intentos_fallidos",
                    detalle=alerta["detalle"],
                    extra={
                        "ip": ip,
                        "cantidad": cantidad,
                        "umbral": umbral
                    }
                )

    return alertas
