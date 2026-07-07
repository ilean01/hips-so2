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
