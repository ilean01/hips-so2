from core.hips_logger import log_alarma


SHELLS_INTERACTIVAS = {
    "/bin/bash",
    "/bin/sh",
    "/bin/zsh",
    "/bin/ksh",
    "/bin/fish",
}


def _entero_seguro(valor: str):
    try:
        return int(valor)
    except ValueError:
        return None


def parsear_passwd(contenido_passwd: str) -> dict:
    usuarios = {}

    for linea in contenido_passwd.splitlines():
        linea = linea.strip()

        if not linea or linea.startswith("#"):
            continue

        partes = linea.split(":")

        if len(partes) < 7:
            continue

        nombre, _, uid, gid, comentario, home, shell = partes[:7]

        usuarios[nombre] = {
            "nombre": nombre,
            "uid": _entero_seguro(uid),
            "gid": _entero_seguro(gid),
            "comentario": comentario,
            "home": home,
            "shell": shell,
            "linea": linea,
        }

    return usuarios


def crear_baseline_usuarios(contenido_passwd: str) -> dict:
    usuarios = parsear_passwd(contenido_passwd)

    baseline = {}

    for nombre, datos in usuarios.items():
        baseline[nombre] = {
            "uid": datos["uid"],
            "gid": datos["gid"],
            "home": datos["home"],
            "shell": datos["shell"],
        }

    return baseline


def detectar_cambios_usuarios(baseline: dict, contenido_actual_passwd: str) -> list[dict]:
    usuarios_actuales = parsear_passwd(contenido_actual_passwd)
    alertas = []

    for nombre, datos_actuales in usuarios_actuales.items():
        if nombre not in baseline:
            alertas.append({
                "tipo": "usuario_nuevo",
                "usuario": nombre,
                "detalle": f"Se detectó un usuario nuevo: {nombre}",
            })
            continue

        datos_esperados = baseline[nombre]

        if datos_actuales["uid"] != datos_esperados.get("uid"):
            alertas.append({
                "tipo": "uid_modificado",
                "usuario": nombre,
                "detalle": f"El usuario {nombre} cambió de UID",
            })

        shell_anterior = datos_esperados.get("shell")
        shell_actual = datos_actuales["shell"]

        if shell_anterior != shell_actual and shell_actual in SHELLS_INTERACTIVAS:
            alertas.append({
                "tipo": "shell_interactiva_agregada",
                "usuario": nombre,
                "detalle": f"El usuario {nombre} ahora tiene shell interactiva: {shell_actual}",
            })

    for nombre in baseline:
        if nombre not in usuarios_actuales:
            alertas.append({
                "tipo": "usuario_eliminado",
                "usuario": nombre,
                "detalle": f"El usuario {nombre} fue eliminado",
            })

    for nombre, datos in usuarios_actuales.items():
        if nombre != "root" and datos["uid"] == 0:
            alertas.append({
                "tipo": "usuario_uid_0",
                "usuario": nombre,
                "detalle": f"El usuario {nombre} tiene UID 0, equivalente a root",
            })

    return alertas


def analizar_usuarios(baseline: dict, contenido_actual_passwd: str, registrar_alertas: bool = True) -> list[dict]:
    alertas = detectar_cambios_usuarios(baseline, contenido_actual_passwd)

    if registrar_alertas:
        for alerta in alertas:
            severidad = "critica" if alerta["tipo"] == "usuario_uid_0" else "alta"

            log_alarma(
                modulo="user_monitor",
                severidad=severidad,
                evento=alerta["tipo"],
                detalle=alerta["detalle"],
                extra={
                    "usuario": alerta["usuario"],
                    "tipo": alerta["tipo"],
                }
            )

    return alertas
