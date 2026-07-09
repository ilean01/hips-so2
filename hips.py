import argparse
import json
import os
import sys

from core.runner import ejecutar_ciclo_deteccion
from core.engine import procesar_alertas


def _entero_en_rango(valor, minimo=0, maximo=23, defecto=None):
    try:
        numero = int(valor)
    except (TypeError, ValueError):
        return defecto

    if minimo <= numero <= maximo:
        return numero

    return defecto


def construir_entradas_desde_configuracion(configuraciones):
    entradas = {}

    for item in configuraciones or []:
        modulo = item.get("modulo")
        configuracion = item.get("configuracion") or {}

        if modulo == "user_monitor":
            hora_inicio = _entero_en_rango(
                configuracion.get("login_hora_inicio"),
                defecto=6
            )
            hora_fin = _entero_en_rango(
                configuracion.get("login_hora_fin"),
                defecto=23
            )

            entradas["login_hora_inicio"] = hora_inicio
            entradas["login_hora_fin"] = hora_fin

    return entradas


def construir_parser():
    parser = argparse.ArgumentParser(
        description="HIPS - Sistema de detección y prevención basado en host"
    )

    parser.add_argument(
        "--guardar-db",
        action="store_true",
        help="Guarda las alertas detectadas en PostgreSQL"
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Muestra la salida en formato JSON"
    )

    parser.add_argument(
        "--sin-logs",
        action="store_true",
        help="No escribe alertas en archivos de log durante esta ejecución"
    )

    parser.add_argument(
        "--enviar-email",
        action="store_true",
        help="Envía un correo al administrador si se detectan alertas"
    )

    parser.add_argument(
        "--admin-email",
        default=os.environ.get("HIPS_ADMIN_EMAIL", ""),
        help="Correo del administrador. También puede configurarse con HIPS_ADMIN_EMAIL"
    )

    parser.add_argument(
        "--sendmail-path",
        default=os.environ.get("HIPS_SENDMAIL_PATH", "/usr/sbin/sendmail"),
        help="Ruta del binario sendmail"
    )

    parser.add_argument(
        "--prevenir",
        action="store_true",
        help="Ejecuta acciones automáticas de prevención cuando se detectan alertas"
    )

    parser.add_argument(
        "--prevenir-dry-run",
        action="store_true",
        help="Simula las acciones de prevención sin ejecutarlas realmente"
    )

    return parser


def ejecutar_hips(args=None):
    parser = construir_parser()
    opciones = parser.parse_args(args)

    conexion = None
    entradas = {}

    if opciones.guardar_db:
        from db.connection import obtener_conexion
        from db.repository import obtener_configuracion_modulos

        conexion = obtener_conexion()
        configuraciones = obtener_configuracion_modulos(conexion)
        entradas = construir_entradas_desde_configuracion(configuraciones)

    if entradas:
        alertas_por_modulo = ejecutar_ciclo_deteccion(
            entradas=entradas,
            registrar_alertas_logs=not opciones.sin_logs
        )
    else:
        alertas_por_modulo = ejecutar_ciclo_deteccion(
            registrar_alertas_logs=not opciones.sin_logs
        )

    resultado = procesar_alertas(
        alertas_por_modulo,
        conexion=conexion,
        guardar_en_db=opciones.guardar_db,
        enviar_email=opciones.enviar_email,
        admin_email=opciones.admin_email,
        sendmail_path=opciones.sendmail_path
    )

    if opciones.prevenir:
        from prevention.engine import prevenir_alertas, registrar_acciones_prevencion_db, marcar_alarmas_prevenidas_resueltas

        resultado["prevencion"] = prevenir_alertas(
            alertas_por_modulo,
            dry_run=opciones.prevenir_dry_run
        )

        if opciones.guardar_db and not opciones.prevenir_dry_run:
            resultado["acciones_prevencion_db"] = registrar_acciones_prevencion_db(
                conexion,
                resultado.get("persistencia"),
                resultado.get("prevencion")
            )

            resultado["resolucion_automatica"] = marcar_alarmas_prevenidas_resueltas(
                conexion,
                resultado.get("persistencia"),
                resultado.get("prevencion")
            )
        else:
            resultado["acciones_prevencion_db"] = None
            resultado["resolucion_automatica"] = None
    else:
        resultado["prevencion"] = None
        resultado["acciones_prevencion_db"] = None
        resultado["resolucion_automatica"] = None

    if conexion is not None:
        conexion.close()

    if opciones.json:
        print(json.dumps(resultado, indent=2, ensure_ascii=False))
    else:
        resumen = resultado["resumen"]
        print("HIPS - Resumen de ejecución")
        print(f"Total de alertas: {resumen['total_alertas']}")

        for modulo, datos in resumen["modulos"].items():
            print(f"- {modulo}: {datos['cantidad']} alerta(s)")

        if resultado.get("email") is not None:
            estado = "enviado" if resultado["email"].get("enviado") else "no enviado"
            print(f"Email administrador: {estado}")

    return resultado


def main():
    try:
        ejecutar_hips()
    except Exception as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
