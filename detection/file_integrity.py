from pathlib import Path
import hashlib
import json

from core.hips_logger import log_alarma


def calcular_sha256(ruta: str) -> str:
    path = Path(ruta)

    if not path.exists():
        raise FileNotFoundError(f"No existe el archivo: {ruta}")

    sha256 = hashlib.sha256()

    with open(path, "rb") as archivo:
        for bloque in iter(lambda: archivo.read(8192), b""):
            sha256.update(bloque)

    return sha256.hexdigest()


def crear_baseline(rutas: list[str]) -> dict:
    baseline = {}

    for ruta in rutas:
        path = Path(ruta)

        if not path.exists():
            baseline[str(path)] = {
                "estado": "no_existe",
                "sha256": None,
                "tamano": None
            }
            continue

        baseline[str(path)] = {
            "estado": "ok",
            "sha256": calcular_sha256(str(path)),
            "tamano": path.stat().st_size
        }

    return baseline


def guardar_baseline(baseline: dict, ruta_salida: str) -> None:
    path = Path(ruta_salida)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as archivo:
        json.dump(baseline, archivo, indent=2, ensure_ascii=False)


def cargar_baseline(ruta_baseline: str) -> dict:
    with open(ruta_baseline, "r", encoding="utf-8") as archivo:
        return json.load(archivo)


def verificar_integridad(baseline: dict, registrar_alertas: bool = True) -> list[dict]:
    alertas = []

    for ruta, datos_esperados in baseline.items():
        path = Path(ruta)

        if not path.exists():
            alerta = {
                "archivo": ruta,
                "tipo": "archivo_eliminado",
                "detalle": f"El archivo {ruta} ya no existe"
            }
            alertas.append(alerta)

            if registrar_alertas:
                log_alarma(
                    modulo="integridad_archivos",
                    severidad="alta",
                    evento="archivo_eliminado",
                    detalle=alerta["detalle"],
                    extra={"archivo": ruta}
                )

            continue

        sha_actual = calcular_sha256(ruta)
        sha_esperado = datos_esperados.get("sha256")

        if sha_actual != sha_esperado:
            alerta = {
                "archivo": ruta,
                "tipo": "archivo_modificado",
                "detalle": f"El archivo {ruta} fue modificado"
            }
            alertas.append(alerta)

            if registrar_alertas:
                log_alarma(
                    modulo="integridad_archivos",
                    severidad="alta",
                    evento="archivo_modificado",
                    detalle=alerta["detalle"],
                    extra={
                        "archivo": ruta,
                        "sha_esperado": sha_esperado,
                        "sha_actual": sha_actual
                    }
                )

    return alertas


# HIPS_BASELINE_DB_STORAGE
# Permite guardar/cargar el baseline de integridad desde PostgreSQL usando db://baseline_archivos.
import os as _hips_os_baseline_db
import json as _hips_json_baseline_db

_hips_guardar_baseline_archivo_original = guardar_baseline
_hips_cargar_baseline_archivo_original = cargar_baseline


def _hips_baseline_db_conn():
    import psycopg2

    return psycopg2.connect(
        dbname=_hips_os_baseline_db.environ.get("HIPS_DB_NAME", "hips_db"),
        user=_hips_os_baseline_db.environ.get("HIPS_DB_USER", "hips_app"),
        password=_hips_os_baseline_db.environ.get("HIPS_DB_PASSWORD"),
        host=_hips_os_baseline_db.environ.get("HIPS_DB_HOST", "127.0.0.1"),
    )


def _hips_asegurar_tabla_baseline_db(conn):
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS baseline_archivos (
                ruta TEXT PRIMARY KEY,
                sha256 TEXT,
                metadata JSONB DEFAULT '{}'::jsonb,
                actualizado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        cur.execute("ALTER TABLE baseline_archivos ADD COLUMN IF NOT EXISTS ruta TEXT;")
        cur.execute("ALTER TABLE baseline_archivos ADD COLUMN IF NOT EXISTS sha256 TEXT;")
        cur.execute("ALTER TABLE baseline_archivos ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}'::jsonb;")
        cur.execute("ALTER TABLE baseline_archivos ADD COLUMN IF NOT EXISTS actualizado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP;")
        cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_baseline_archivos_ruta ON baseline_archivos(ruta);")
    conn.commit()


def _hips_es_destino_db_baseline(ruta):
    return str(ruta).startswith("db://")


def guardar_baseline(baseline, archivo="config/baseline_archivos.json"):
    if not _hips_es_destino_db_baseline(archivo):
        return _hips_guardar_baseline_archivo_original(baseline, archivo)

    conn = _hips_baseline_db_conn()
    try:
        _hips_asegurar_tabla_baseline_db(conn)

        with conn.cursor() as cur:
            for ruta, metadata in (baseline or {}).items():
                if not isinstance(metadata, dict):
                    metadata = {"valor": metadata}

                sha256 = (
                    metadata.get("sha256")
                    or metadata.get("hash")
                    or metadata.get("hash_sha256")
                    or ""
                )

                cur.execute(
                    """
                    INSERT INTO baseline_archivos (ruta, sha256, metadata, actualizado_en)
                    VALUES (%s, %s, %s::jsonb, CURRENT_TIMESTAMP)
                    ON CONFLICT (ruta)
                    DO UPDATE SET
                        sha256 = EXCLUDED.sha256,
                        metadata = EXCLUDED.metadata,
                        actualizado_en = CURRENT_TIMESTAMP;
                    """,
                    (ruta, sha256, _hips_json_baseline_db.dumps(metadata, ensure_ascii=False)),
                )

        conn.commit()
    finally:
        conn.close()


def cargar_baseline(archivo="config/baseline_archivos.json"):
    if not _hips_es_destino_db_baseline(archivo):
        return _hips_cargar_baseline_archivo_original(archivo)

    try:
        conn = _hips_baseline_db_conn()
        try:
            _hips_asegurar_tabla_baseline_db(conn)

            with conn.cursor() as cur:
                cur.execute("SELECT ruta, metadata FROM baseline_archivos ORDER BY ruta;")
                filas = cur.fetchall()

            if filas:
                resultado = {}
                for ruta, metadata in filas:
                    if isinstance(metadata, str):
                        metadata = _hips_json_baseline_db.loads(metadata)
                    resultado[ruta] = metadata
                return resultado

        finally:
            conn.close()

    except Exception:
        pass

    # Fallback local solo para desarrollo/tests si la DB no está disponible.
    try:
        return _hips_cargar_baseline_archivo_original("config/baseline_archivos.json")
    except Exception:
        return {}


def migrar_baseline_json_a_db(origen="config/baseline_archivos.json", destino="db://baseline_archivos"):
    baseline = _hips_cargar_baseline_archivo_original(origen)
    guardar_baseline(baseline, destino)
    return len(baseline or {})
