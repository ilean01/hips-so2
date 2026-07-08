import argparse
import json
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
        guardar_en_db=opciones.guardar_db
    )

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
