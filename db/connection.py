import os
import psycopg2


def obtener_conexion():
    return psycopg2.connect(
        dbname=os.environ.get("HIPS_DB_NAME", "hips_db"),
        user=os.environ.get("HIPS_DB_USER", "postgres"),
        password=os.environ.get("HIPS_DB_PASSWORD"),
        host=os.environ.get("HIPS_DB_HOST"),
        port=os.environ.get("HIPS_DB_PORT", "5432"),
    )
