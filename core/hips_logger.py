from datetime import datetime
from pathlib import Path
import json
import os


DEFAULT_LOG_DIR = "/var/log/hips"
ALARMAS_LOG = "alarmas.log"
ALARMAS_DETALLE_LOG = "alarmas_detalle.jsonl"
PREVENCION_LOG = "prevencion.log"


def _get_log_dir() -> Path:
    return Path(os.environ.get("HIPS_LOG_DIR", DEFAULT_LOG_DIR))


def _clean_text(value) -> str:
    text = str(value)
    return text.replace("\n", " ").replace("\r", " ").strip()


def _timestamp_iso() -> str:
    return datetime.now().isoformat()


def _timestamp_obligatorio() -> str:
    return datetime.now().strftime("%d/%m/%Y")


def _normalizar_tipo(evento: str) -> str:
    return _clean_text(evento).upper()


def _obtener_ip_origen(extra=None) -> str:
    if not extra:
        return "N/A"

    posibles_claves = [
        "ip_origen",
        "ip",
        "origen",
        "source_ip",
        "remote_ip",
    ]

    for clave in posibles_claves:
        valor = extra.get(clave)
        if valor:
            return _clean_text(valor)

    return "N/A"


def _asegurar_directorio(log_dir: Path) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)


def _append_line(log_path: Path, linea: str) -> None:
    try:
        with open(log_path, "a", encoding="utf-8") as file:
            file.write(linea + "\n")
    except PermissionError as error:
        raise PermissionError(
            f"No hay permiso para escribir en {log_path}. "
            "Verificar usuario hips_svc, grupo hips_group y permisos de /var/log/hips."
        ) from error


def _registro_json(modulo: str, severidad: str, evento: str, detalle: str, extra=None) -> str:
    registro = {
        "timestamp": _timestamp_iso(),
        "modulo": _clean_text(modulo),
        "severidad": _clean_text(severidad),
        "evento": _clean_text(evento),
        "detalle": _clean_text(detalle),
        "extra": extra or {},
    }

    return json.dumps(registro, ensure_ascii=False)


def _linea_alarma_obligatoria(evento: str, extra=None) -> str:
    timestamp = _timestamp_obligatorio()
    tipo_alarma = _normalizar_tipo(evento)
    ip_origen = _obtener_ip_origen(extra)

    return f"{timestamp} :: {tipo_alarma} :: {ip_origen}"


def log_alarma(modulo: str, severidad: str, evento: str, detalle: str, extra=None) -> None:
    log_dir = _get_log_dir()
    _asegurar_directorio(log_dir)

    linea_obligatoria = _linea_alarma_obligatoria(evento, extra)
    linea_detalle = _registro_json(modulo, severidad, evento, detalle, extra)

    _append_line(log_dir / ALARMAS_LOG, linea_obligatoria)
    _append_line(log_dir / ALARMAS_DETALLE_LOG, linea_detalle)


def log_prevencion(modulo: str, severidad: str, evento: str, detalle: str, extra=None) -> None:
    log_dir = _get_log_dir()
    _asegurar_directorio(log_dir)

    linea = _registro_json(modulo, severidad, evento, detalle, extra)
    _append_line(log_dir / PREVENCION_LOG, linea)
