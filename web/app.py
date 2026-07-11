import json
import os
from functools import wraps

from flask import Flask, redirect, render_template, request, session, url_for

from db.connection import obtener_conexion


def _filas_como_diccionarios(cursor):
    columnas = [columna[0] for columna in cursor.description]
    return [dict(zip(columnas, fila)) for fila in cursor.fetchall()]


def consultar_dashboard():
    conn = obtener_conexion()
    cur = conn.cursor()

    cur.execute("""
        SELECT id, timestamp, tipo_alarma, modulo, severidad, ip_origen, resuelta, descripcion
        FROM alarmas
        ORDER BY id DESC
        LIMIT 50;
    """)
    alarmas = _filas_como_diccionarios(cur)

    cur.execute("""
        SELECT id, timestamp, modulo, evento, detalle
        FROM eventos_sistema
        ORDER BY id DESC
        LIMIT 20;
    """)
    eventos = _filas_como_diccionarios(cur)

    cur.execute("""
        SELECT modulo, COUNT(*) AS cantidad
        FROM alarmas
        WHERE resuelta = false
        GROUP BY modulo
        ORDER BY cantidad DESC;
    """)
    alarmas_por_modulo = _filas_como_diccionarios(cur)

    cur.execute("""
        SELECT severidad, COUNT(*) AS cantidad
        FROM alarmas
        WHERE resuelta = false
        GROUP BY severidad
        ORDER BY cantidad DESC;
    """)
    alarmas_por_severidad = _filas_como_diccionarios(cur)

    cur.execute("""
        SELECT modulo, habilitado, intervalo_segundos, umbral, configuracion
        FROM configuracion_modulos
        ORDER BY modulo;
    """)
    modulos = _filas_como_diccionarios(cur)

    for modulo in modulos:
        configuracion = modulo.get("configuracion") or {}

        if isinstance(configuracion, str):
            configuracion = json.loads(configuracion)

        modulo["configuracion"] = configuracion

    cur.execute("""
        SELECT
            ap.id,
            ap.timestamp,
            ap.alarma_id,
            a.modulo,
            a.tipo_alarma,
            ap.accion,
            ap.resultado,
            ap.detalle
        FROM acciones_prevencion ap
        JOIN alarmas a ON a.id = ap.alarma_id
        ORDER BY ap.id DESC
        LIMIT 30;
    """)
    acciones_prevencion = _filas_como_diccionarios(cur)

    cur.close()
    conn.close()

    return {
        "alarmas": alarmas,
        "eventos": eventos,
        "alarmas_por_modulo": alarmas_por_modulo,
        "alarmas_por_severidad": alarmas_por_severidad,
        "modulos": modulos,
        "acciones_prevencion": acciones_prevencion,
    }


def marcar_alarma_resuelta(alarma_id: int) -> None:
    conn = obtener_conexion()
    cur = conn.cursor()

    cur.execute(
        """
        UPDATE alarmas
        SET resuelta = true
        WHERE id = %s AND resuelta = false
        RETURNING id;
        """,
        (alarma_id,)
    )

    alarma_actualizada = cur.fetchone()

    if alarma_actualizada:
        cur.execute(
            """
            INSERT INTO eventos_sistema (modulo, evento, detalle)
            VALUES (%s, %s, %s);
            """,
            (
                "web",
                "alarma_resuelta",
                f"Alarma {alarma_id} marcada como resuelta desde el dashboard"
            )
        )

    conn.commit()
    cur.close()
    conn.close()


def actualizar_configuracion_modulo(
    modulo: str,
    habilitado: bool,
    intervalo_segundos: int,
    umbral,
    configuracion=None
) -> None:
    conn = obtener_conexion()
    cur = conn.cursor()

    cur.execute(
        """
        UPDATE configuracion_modulos
        SET habilitado = %s,
            intervalo_segundos = %s,
            umbral = %s,
            configuracion = COALESCE(%s::jsonb, configuracion)
        WHERE modulo = %s;
        """,
        (
            habilitado,
            intervalo_segundos,
            umbral,
            json.dumps(configuracion) if configuracion is not None else None,
            modulo
        )
    )

    cur.execute(
        """
        INSERT INTO eventos_sistema (modulo, evento, detalle)
        VALUES (%s, %s, %s);
        """,
        (
            "web",
            "modulo_actualizado",
            f"Módulo {modulo} actualizado desde el dashboard"
        )
    )

    conn.commit()
    cur.close()
    conn.close()


def crear_app(dashboard_provider=None, resolver_provider=None, modulo_provider=None):
    app = Flask(__name__)
    app.secret_key = os.environ.get("HIPS_WEB_SECRET_KEY")
    app.config["HIPS_WEB_USER"] = os.environ.get("HIPS_WEB_USER", "admin")
    app.config["HIPS_WEB_PASSWORD"] = os.environ.get("HIPS_WEB_PASSWORD")

    if not app.secret_key:
        raise RuntimeError("Falta configurar HIPS_WEB_SECRET_KEY")

    if not app.config["HIPS_WEB_PASSWORD"]:
        raise RuntimeError("Falta configurar HIPS_WEB_PASSWORD")

    app.config["HIPS_WEB_USER"] = os.environ.get("HIPS_WEB_USER", "admin")
    app.config["HIPS_WEB_PASSWORD"] = os.environ.get("HIPS_WEB_PASSWORD")
    app.config["DASHBOARD_PROVIDER"] = dashboard_provider or consultar_dashboard
    app.config["RESOLVER_PROVIDER"] = resolver_provider or marcar_alarma_resuelta
    app.config["MODULO_PROVIDER"] = modulo_provider or actualizar_configuracion_modulo

    def login_requerido(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not session.get("autenticado"):
                return redirect(url_for("login"))
            return func(*args, **kwargs)
        return wrapper

    @app.route("/", methods=["GET"])
    def index():
        if session.get("autenticado"):
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None

        if request.method == "POST":
            usuario = request.form.get("usuario", "")
            password = request.form.get("password", "")

            if (
                usuario == app.config["HIPS_WEB_USER"]
                and password == app.config["HIPS_WEB_PASSWORD"]
            ):
                session["autenticado"] = True
                session["usuario"] = usuario
                return redirect(url_for("dashboard"))

            error = "Usuario o contraseña incorrectos"

        return render_template("login.html", error=error)

    @app.route("/dashboard", methods=["GET"])
    @login_requerido
    def dashboard():
        datos = app.config["DASHBOARD_PROVIDER"]()
        return render_template("dashboard.html", datos=datos, usuario=session.get("usuario"))

    @app.route("/alarmas/<int:alarma_id>/resolver", methods=["POST"])
    @login_requerido
    def resolver_alarma(alarma_id):
        app.config["RESOLVER_PROVIDER"](alarma_id)
        return redirect(url_for("dashboard"))

    @app.route("/modulos/<modulo>/actualizar", methods=["POST"])
    @login_requerido
    def actualizar_modulo(modulo):
        habilitado = request.form.get("habilitado") == "on"
        intervalo_segundos = int(request.form.get("intervalo_segundos", "60"))

        umbral_texto = request.form.get("umbral", "").strip()
        umbral = int(umbral_texto) if umbral_texto else None

        configuracion = None

        if modulo == "user_monitor":
            login_hora_inicio = int(request.form.get("login_hora_inicio", "6"))
            login_hora_fin = int(request.form.get("login_hora_fin", "23"))

            login_hora_inicio = max(0, min(23, login_hora_inicio))
            login_hora_fin = max(0, min(23, login_hora_fin))

            configuracion = {
                "login_hora_inicio": login_hora_inicio,
                "login_hora_fin": login_hora_fin,
            }

        if configuracion is None:
            app.config["MODULO_PROVIDER"](
                modulo,
                habilitado,
                intervalo_segundos,
                umbral
            )
        else:
            app.config["MODULO_PROVIDER"](
                modulo,
                habilitado,
                intervalo_segundos,
                umbral,
                configuracion
            )

        return redirect(url_for("dashboard"))

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        return redirect(url_for("login"))

    return app


app = crear_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
