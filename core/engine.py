from core.alert_service import registrar_alertas_db


def contar_alertas(alertas_por_modulo: dict) -> int:
    total = 0

    for alertas in alertas_por_modulo.values():
        total += len(alertas)

    return total


def generar_resumen(alertas_por_modulo: dict) -> dict:
    resumen = {
        "total_alertas": contar_alertas(alertas_por_modulo),
        "modulos": {}
    }

    for modulo, alertas in alertas_por_modulo.items():
        resumen["modulos"][modulo] = {
            "cantidad": len(alertas),
            "tipos": {}
        }

        for alerta in alertas:
            tipo = alerta.get("tipo", "desconocida")
            resumen["modulos"][modulo]["tipos"][tipo] = (
                resumen["modulos"][modulo]["tipos"].get(tipo, 0) + 1
            )

    return resumen


def persistir_alertas(conexion, alertas_por_modulo: dict) -> dict:
    resultado = {}

    for modulo, alertas in alertas_por_modulo.items():
        ids = registrar_alertas_db(conexion, modulo, alertas)

        resultado[modulo] = {
            "cantidad": len(ids),
            "ids": ids
        }

    return resultado


def procesar_alertas(alertas_por_modulo: dict, conexion=None, guardar_en_db: bool = False) -> dict:
    resumen = generar_resumen(alertas_por_modulo)

    resultado = {
        "resumen": resumen,
        "persistencia": None
    }

    if guardar_en_db:
        if conexion is None:
            raise ValueError("Se requiere una conexión para guardar alertas en PostgreSQL")

        resultado["persistencia"] = persistir_alertas(conexion, alertas_por_modulo)

    return resultado
