from pathlib import Path
import os
import re
import stat

from core.hips_logger import log_alarma


EXTENSIONES_SOSPECHOSAS = {
    ".sh",
    ".py",
    ".pl",
    ".rb",
    ".elf",
    ".bin",
    ".run",
}

NOMBRES_SOSPECHOSOS = {
    "nc",
    "netcat",
    "ncat",
    "socat",
    "xmrig",
    "miner",
    "backdoor",
    "reverse_shell",
}


def _es_world_writable(modo: int) -> bool:
    return bool(modo & stat.S_IWOTH)


def _es_ejecutable(ruta: Path) -> bool:
    return os.access(str(ruta), os.X_OK)


def _es_lock_legitimo_tmp(path: Path) -> bool:
    nombre = path.name

    if re.match(r"^\.X\d+-lock$", nombre):
        return True

    if re.match(r"^\.s\.PGSQL\.\d+\.lock$", nombre):
        return True

    return False


def analizar_archivo_tmp(ruta_archivo: str) -> list[dict]:
    path = Path(ruta_archivo)
    alertas = []

    if not path.exists() or not path.is_file():
        return alertas

    if _es_lock_legitimo_tmp(path):
        return alertas

    nombre = path.name.lower()
    extension = path.suffix.lower()
    modo = path.stat().st_mode

    if path.name.startswith("."):
        alertas.append({
            "tipo": "archivo_oculto_tmp",
            "archivo": str(path),
            "detalle": f"Archivo oculto detectado en tmp: {path}",
        })

    if extension in EXTENSIONES_SOSPECHOSAS:
        alertas.append({
            "tipo": "extension_sospechosa_tmp",
            "archivo": str(path),
            "detalle": f"Archivo con extensión sospechosa en tmp: {path}",
        })

    if _es_ejecutable(path):
        alertas.append({
            "tipo": "ejecutable_en_tmp",
            "archivo": str(path),
            "detalle": f"Archivo ejecutable detectado en tmp: {path}",
        })

    if _es_world_writable(modo):
        alertas.append({
            "tipo": "archivo_world_writable_tmp",
            "archivo": str(path),
            "detalle": f"Archivo modificable por todos detectado en tmp: {path}",
        })

    for nombre_sospechoso in NOMBRES_SOSPECHOSOS:
        if nombre_sospechoso in nombre:
            alertas.append({
                "tipo": "nombre_sospechoso_tmp",
                "archivo": str(path),
                "detalle": f"Nombre sospechoso detectado en tmp: {path}",
            })
            break

    return alertas


def escanear_tmp(ruta_tmp: str = "/tmp", registrar_alertas: bool = True) -> list[dict]:
    base = Path(ruta_tmp)

    if not base.exists():
        raise FileNotFoundError(f"No existe el directorio temporal: {ruta_tmp}")

    alertas = []

    for path in base.rglob("*"):
        if not path.is_file():
            continue

        alertas_archivo = analizar_archivo_tmp(str(path))
        alertas.extend(alertas_archivo)

    if registrar_alertas:
        for alerta in alertas:
            log_alarma(
                modulo="tmp_monitor",
                severidad="alta",
                evento=alerta["tipo"],
                detalle=alerta["detalle"],
                extra={
                    "archivo": alerta["archivo"],
                    "tipo": alerta["tipo"],
                }
            )

    return alertas
