from pathlib import Path
import os
import re
import shutil
import signal
import subprocess

from core.hips_logger import log_prevencion
from detection.file_integrity import calcular_sha256


def validar_ip(ip: str) -> bool:
    if not re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", ip):
        return False

    partes = ip.split(".")
    return all(0 <= int(parte) <= 255 for parte in partes)


def _ejecutar_comando(comando: list) -> dict:
    resultado = subprocess.run(
        comando,
        check=True,
        text=True,
        capture_output=True
    )

    return {
        "stdout": resultado.stdout,
        "stderr": resultado.stderr,
        "returncode": resultado.returncode,
    }


def bloquear_ip(ip: str, dry_run: bool = True) -> dict:
    if not validar_ip(ip):
        raise ValueError(f"IP inválida: {ip}")

    comando_bloqueo = [
        "sudo",
        "firewall-cmd",
        "--permanent",
        f'--add-rich-rule=rule family="ipv4" source address="{ip}" reject'
    ]

    comando_reload = [
        "sudo",
        "firewall-cmd",
        "--reload"
    ]

    accion = {
        "accion": "bloquear_ip",
        "ip": ip,
        "dry_run": dry_run,
        "comandos": [
            " ".join(comando_bloqueo),
            " ".join(comando_reload),
        ],
        "ejecutado": False,
    }

    if not dry_run:
        _ejecutar_comando(comando_bloqueo)
        _ejecutar_comando(comando_reload)
        accion["ejecutado"] = True

    log_prevencion(
        modulo="prevention_actions",
        severidad="alta",
        evento="bloquear_ip",
        detalle=f"Acción de prevención para bloquear IP {ip}",
        extra=accion
    )

    return accion


def finalizar_proceso(pid: int, senal: int = signal.SIGTERM, dry_run: bool = True) -> dict:
    try:
        pid = int(pid)
    except ValueError:
        raise ValueError("PID inválido")

    if pid <= 0:
        raise ValueError("PID inválido")

    accion = {
        "accion": "finalizar_proceso",
        "pid": pid,
        "senal": int(senal),
        "dry_run": dry_run,
        "ejecutado": False,
    }

    if not dry_run:
        os.kill(pid, senal)
        accion["ejecutado"] = True

    log_prevencion(
        modulo="prevention_actions",
        severidad="alta",
        evento="finalizar_proceso",
        detalle=f"Acción de prevención para finalizar proceso {pid}",
        extra=accion
    )

    return accion


def cuarentenar_archivo(ruta_archivo: str, ruta_cuarentena: str = "/var/quarantine/hips", dry_run: bool = True) -> dict:
    origen = Path(ruta_archivo)

    if not origen.exists() or not origen.is_file():
        raise FileNotFoundError(f"No existe el archivo a cuarentenar: {ruta_archivo}")

    sha256 = calcular_sha256(str(origen))
    destino_dir = Path(ruta_cuarentena)
    destino = destino_dir / f"{origen.name}.{sha256[:12]}.quarantine"

    accion = {
        "accion": "cuarentenar_archivo",
        "origen": str(origen),
        "destino": str(destino),
        "sha256": sha256,
        "dry_run": dry_run,
        "ejecutado": False,
    }

    if not dry_run:
        destino_dir.mkdir(parents=True, exist_ok=True)
        shutil.move(str(origen), str(destino))
        accion["ejecutado"] = True

    log_prevencion(
        modulo="prevention_actions",
        severidad="alta",
        evento="cuarentenar_archivo",
        detalle=f"Acción de prevención para mover archivo a cuarentena: {origen}",
        extra=accion
    )

    return accion
