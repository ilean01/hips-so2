from datetime import datetime, timezone
from pathlib import Path
import json
import os


DEFAULT_LOG_DIR = "/var/log/hips"
ALARMAS_LOG = "alarmas.log"
PREVENCION_LOG = "prevencion.log"


def _get_log_dir() -> Path:
    return Path(os.environ.get("HIPS_LOG_DIR", DEFAULT_LOG_DIR))


def _clean_text(value) -> str:
    text = str(value)
    return text.replace("\n", " ").replace("\r", " ").strip()


def _write_log(filename: str, modulo: str, severidad: str, evento: str, detalle: str, extra=None) -> None:
    log_dir = _get_log_dir()
    log_path = log_dir / filename

    timestamp = datetime.now(timezone.utc).isoformat()

    registro = {
        "timestamp": timestamp,
        "modulo": _clean_text(modulo),
        "severidad": _clean_text(severidad),
        "evento": _clean_text(evento),
        "detalle": _clean_text(detalle),
        "extra": extra or {}
    }

    linea = json.dumps(registro, ensure_ascii=False)

    try:
        with open(log_path, "a", encoding="utf-8") as file:
            file.write(linea + "\n")
    except PermissionError as error:
        raise PermissionError(
            f"No hay permiso para escribir en {log_path}. "
            "Verificar usuario hips_svc, grupo hips_group y permisos de /var/log/hips."
        ) from error


def log_alarma(modulo: str, severidad: str, evento: str, detalle: str, extra=None) -> None:
    _write_log(ALARMAS_LOG, modulo, severidad, evento, detalle, extra)


def log_prevencion(modulo: str, severidad: str, evento: str, detalle: str, extra=None) -> None:
    _write_log(PREVENCION_LOG, modulo, severidad, evento, detalle, extra)
