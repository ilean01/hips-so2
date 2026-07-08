from core.alert_service import registrar_alertas_db
from core.email_notifier import enviar_email_admin


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


def procesar_alertas(
    alertas_por_modulo: dict,
    conexion=None,
    guardar_en_db: bool = False,
    enviar_email: bool = False,
    admin_email: str = "",
    sendmail_path: str = "/usr/sbin/sendmail"
) -> dict:
    resumen = generar_resumen(alertas_por_modulo)

    resultado = {
        "resumen": resumen,
        "persistencia": None,
        "email": None
    }

    if guardar_en_db:
        if conexion is None:
            raise ValueError("Se requiere una conexión para guardar alertas en PostgreSQL")

        resultado["persistencia"] = persistir_alertas(conexion, alertas_por_modulo)

    if enviar_email:
        resultado["email"] = enviar_email_admin(
            alertas_por_modulo,
            admin_email=admin_email,
            sendmail_path=sendmail_path
        )

    return resultado
