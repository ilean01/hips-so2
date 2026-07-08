import argparse
import json
import os
import sys

from core.runner import ejecutar_ciclo_deteccion
from core.engine import procesar_alertas


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

    alertas_por_modulo = ejecutar_ciclo_deteccion(
        registrar_alertas_logs=not opciones.sin_logs
    )

    conexion = None

    if opciones.guardar_db:
        from db.connection import obtener_conexion
        conexion = obtener_conexion()

    resultado = procesar_alertas(
        alertas_por_modulo,
        conexion=conexion,
        guardar_en_db=opciones.guardar_db,
        enviar_email=opciones.enviar_email,
        admin_email=opciones.admin_email,
        sendmail_path=opciones.sendmail_path
    )

    if opciones.prevenir:
        from prevention.engine import prevenir_alertas, marcar_alarmas_prevenidas_resueltas

        resultado["prevencion"] = prevenir_alertas(
            alertas_por_modulo,
            dry_run=opciones.prevenir_dry_run
        )

        if opciones.guardar_db and not opciones.prevenir_dry_run:
            resultado["resolucion_automatica"] = marcar_alarmas_prevenidas_resueltas(
                conexion,
                resultado.get("persistencia"),
                resultado.get("prevencion")
            )
        else:
            resultado["resolucion_automatica"] = None
    else:
        resultado["prevencion"] = None
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
