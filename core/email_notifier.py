import os
import socket
import subprocess
from datetime import datetime


DEFAULT_SENDMAIL = "/usr/sbin/sendmail"


def _limpiar_texto(valor) -> str:
    return str(valor).replace("\n", " ").replace("\r", " ").strip()


def _obtener_hostname() -> str:
    return socket.gethostname()


def construir_cuerpo_email(alertas_por_modulo: dict, hostname=None) -> str:
    hostname = hostname or _obtener_hostname()
    timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    lineas = [
        "Alerta del sistema HIPS",
        "",
        f"Host: {hostname}",
        f"Fecha: {timestamp}",
        "",
        "Resumen de alertas:",
    ]

    total = 0

    for modulo, alertas in alertas_por_modulo.items():
        total += len(alertas)
        lineas.append(f"- {modulo}: {len(alertas)} alerta(s)")

        for alerta in alertas:
            tipo = _limpiar_texto(alerta.get("tipo", "desconocida"))
            detalle = _limpiar_texto(alerta.get("detalle", "Sin detalle"))
            lineas.append(f"  * {tipo}: {detalle}")

    lineas.insert(4, f"Total de alertas: {total}")

    return "\n".join(lineas) + "\n"


def enviar_email_admin(
    alertas_por_modulo: dict,
    admin_email: str,
    sendmail_path: str = DEFAULT_SENDMAIL,
    remitente: str = "hips@localhost"
) -> dict:
    total_alertas = sum(len(alertas) for alertas in alertas_por_modulo.values())

    resultado = {
        "enviado": False,
        "total_alertas": total_alertas,
        "admin_email": admin_email,
        "sendmail_path": sendmail_path,
        "returncode": None,
        "stderr": "",
    }

    if total_alertas == 0:
        resultado["motivo"] = "sin_alertas"
        return resultado

    if not admin_email:
        resultado["motivo"] = "admin_email_no_configurado"
        return resultado

    asunto = f"[HIPS] {total_alertas} alerta(s) detectada(s) en {_obtener_hostname()}"
    cuerpo = construir_cuerpo_email(alertas_por_modulo)

    mensaje = (
        f"From: {remitente}\n"
        f"To: {admin_email}\n"
        f"Subject: {asunto}\n"
        "Content-Type: text/plain; charset=UTF-8\n"
        "\n"
        f"{cuerpo}"
    )

    proceso = subprocess.run(
        [sendmail_path, "-t"],
        input=mensaje,
        text=True,
        capture_output=True,
        check=False
    )

    resultado["returncode"] = proceso.returncode
    resultado["stderr"] = proceso.stderr.strip()
    resultado["enviado"] = proceso.returncode == 0

    if not resultado["enviado"]:
        resultado["motivo"] = "sendmail_error"

    return resultado


def obtener_admin_email_desde_entorno() -> str:
    return os.environ.get("HIPS_ADMIN_EMAIL", "")
