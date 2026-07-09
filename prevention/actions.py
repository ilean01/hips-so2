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


USUARIOS_PROTEGIDOS = {
    "root",
    "ile",
    "postgres",
    "hips_app",
    "hips_svc",
}


def _usuario_valido(usuario: str) -> bool:
    return bool(re.match(r"^[a-z_][a-z0-9_-]*\$?$", usuario or ""))


def _accion_protegida(nombre_accion: str, usuario: str, dry_run: bool) -> dict:
    accion = {
        "accion": nombre_accion,
        "usuario": usuario,
        "dry_run": dry_run,
        "ejecutado": False,
        "motivo": "usuario_protegido",
    }

    log_prevencion(
        modulo="prevention_actions",
        severidad="alta",
        evento=nombre_accion,
        detalle=f"No se ejecutó {nombre_accion} sobre usuario protegido: {usuario}",
        extra=accion
    )

    return accion


def bloquear_usuario(usuario: str, dry_run: bool = True) -> dict:
    if not _usuario_valido(usuario):
        raise ValueError(f"Usuario inválido: {usuario}")

    if usuario in USUARIOS_PROTEGIDOS:
        return _accion_protegida("bloquear_usuario", usuario, dry_run)

    comando = [
        "sudo",
        "passwd",
        "-l",
        usuario
    ]

    accion = {
        "accion": "bloquear_usuario",
        "usuario": usuario,
        "dry_run": dry_run,
        "comandos": [" ".join(comando)],
        "ejecutado": False,
    }

    if not dry_run:
        _ejecutar_comando(comando)
        accion["ejecutado"] = True

    log_prevencion(
        modulo="prevention_actions",
        severidad="alta",
        evento="bloquear_usuario",
        detalle=f"Acción de prevención para bloquear usuario {usuario}",
        extra=accion
    )

    return accion


def cambiar_password_usuario(usuario: str, dry_run: bool = True) -> dict:
    import secrets

    if not _usuario_valido(usuario):
        raise ValueError(f"Usuario inválido: {usuario}")

    if usuario in USUARIOS_PROTEGIDOS:
        return _accion_protegida("cambiar_password_usuario", usuario, dry_run)

    nueva_password = secrets.token_urlsafe(24)
    comando_visible = f"echo '{usuario}:********' | sudo chpasswd"

    accion = {
        "accion": "cambiar_password_usuario",
        "usuario": usuario,
        "dry_run": dry_run,
        "comandos": [comando_visible],
        "nueva_password_generada": True,
        "ejecutado": False,
    }

    if not dry_run:
        subprocess.run(
            ["sudo", "chpasswd"],
            input=f"{usuario}:{nueva_password}\n",
            text=True,
            capture_output=True,
            check=True
        )
        accion["ejecutado"] = True

    log_prevencion(
        modulo="prevention_actions",
        severidad="alta",
        evento="cambiar_password_usuario",
        detalle=f"Acción de prevención para cambiar contraseña del usuario {usuario}",
        extra=accion
    )

    return accion


def reiniciar_postfix(dry_run: bool = True) -> dict:
    comando = ["sudo", "systemctl", "restart", "postfix"]

    accion = {
        "accion": "reiniciar_postfix",
        "dry_run": dry_run,
        "comandos": [" ".join(comando)],
        "ejecutado": False,
    }

    if not dry_run:
        _ejecutar_comando(comando)
        accion["ejecutado"] = True

    log_prevencion(
        modulo="prevention_actions",
        severidad="alta",
        evento="reiniciar_postfix",
        detalle="Acción de prevención para reiniciar Postfix",
        extra=accion
    )

    return accion


def pausar_postfix(dry_run: bool = True) -> dict:
    comando = ["sudo", "systemctl", "stop", "postfix"]

    accion = {
        "accion": "pausar_postfix",
        "dry_run": dry_run,
        "comandos": [" ".join(comando)],
        "ejecutado": False,
    }

    if not dry_run:
        _ejecutar_comando(comando)
        accion["ejecutado"] = True

    log_prevencion(
        modulo="prevention_actions",
        severidad="alta",
        evento="pausar_postfix",
        detalle="Acción de prevención para pausar Postfix",
        extra=accion
    )

    return accion


def limpiar_cola_correo(dry_run: bool = True) -> dict:
    comando = ["sudo", "postsuper", "-d", "ALL", "deferred"]

    accion = {
        "accion": "limpiar_cola_correo",
        "dry_run": dry_run,
        "comandos": [" ".join(comando)],
        "ejecutado": False,
        "alcance": "solo_mensajes_deferred",
    }

    if not dry_run:
        _ejecutar_comando(comando)
        accion["ejecutado"] = True

    log_prevencion(
        modulo="prevention_actions",
        severidad="alta",
        evento="limpiar_cola_correo",
        detalle="Acción de prevención para limpiar mensajes diferidos de la cola de correo",
        extra=accion
    )

    return accion


def documentar_integridad_archivo(ruta_archivo: str, motivo: str = "", dry_run: bool = True) -> dict:
    accion = {
        "accion": "documentar_integridad_archivo",
        "archivo": ruta_archivo,
        "motivo": motivo,
        "dry_run": dry_run,
        "ejecutado": not dry_run,
    }

    log_prevencion(
        modulo="prevention_actions",
        severidad="alta",
        evento="documentar_integridad_archivo",
        detalle=f"Acción preventiva documentada para integridad de archivo: {ruta_archivo}",
        extra=accion
    )

    return accion


def desactivar_modo_promiscuo(interfaz: str, dry_run: bool = True) -> dict:
    if not re.match(r"^[a-zA-Z0-9_.:-]+$", interfaz or ""):
        raise ValueError(f"Interfaz inválida: {interfaz}")

    comando = [
        "sudo",
        "ip",
        "link",
        "set",
        interfaz,
        "promisc",
        "off"
    ]

    accion = {
        "accion": "desactivar_modo_promiscuo",
        "interfaz": interfaz,
        "dry_run": dry_run,
        "comandos": [" ".join(comando)],
        "ejecutado": False,
    }

    if not dry_run:
        _ejecutar_comando(comando)
        accion["ejecutado"] = True

    log_prevencion(
        modulo="prevention_actions",
        severidad="alta",
        evento="desactivar_modo_promiscuo",
        detalle=f"Acción de prevención para desactivar modo promiscuo en {interfaz}",
        extra=accion
    )

    return accion
