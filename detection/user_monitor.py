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


def parsear_who(salida_who: str) -> list[dict]:
    sesiones = []

    for linea in salida_who.splitlines():
        linea = linea.strip()

        if not linea:
            continue

        partes = linea.split()

        if len(partes) < 4:
            continue

        usuario = partes[0]
        terminal = partes[1]
        fecha = partes[2]
        hora = partes[3]

        origen = "local"
        if len(partes) >= 5:
            origen = " ".join(partes[4:]).strip()
            origen = origen.strip("()") or "local"

        sesiones.append({
            "usuario": usuario,
            "terminal": terminal,
            "fecha": fecha,
            "hora": hora,
            "origen": origen,
            "linea": linea,
        })

    return sesiones


def _hora_a_entero(hora: str):
    try:
        return int(hora.split(":")[0])
    except (ValueError, IndexError):
        return None


def detectar_usuarios_conectados(
    salida_who: str,
    origenes_permitidos=None,
    hora_inicio: int = 6,
    hora_fin: int = 23
) -> list[dict]:
    sesiones = parsear_who(salida_who)
    alertas = []

    if origenes_permitidos is None:
        origenes_permitidos = {"local", "127.0.0.1", "::1"}

    origenes_permitidos = set(origenes_permitidos)

    for sesion in sesiones:
        origen = sesion["origen"]
        hora = _hora_a_entero(sesion["hora"])

        if origen not in origenes_permitidos:
            alertas.append({
                "tipo": "origen_login_inusual",
                "usuario": sesion["usuario"],
                "origen": origen,
                "detalle": f"Usuario conectado desde origen no permitido: {origen}",
                "sesion": sesion["linea"],
            })

        if hora is not None and not (hora_inicio <= hora <= hora_fin):
            alertas.append({
                "tipo": "login_fuera_horario",
                "usuario": sesion["usuario"],
                "origen": origen,
                "detalle": f"Usuario conectado fuera del horario esperado: {sesion['hora']}",
                "sesion": sesion["linea"],
            })

    return alertas


def analizar_usuarios_conectados(
    salida_who: str,
    origenes_permitidos=None,
    hora_inicio: int = 6,
    hora_fin: int = 23,
    registrar_alertas: bool = True
) -> list[dict]:
    alertas = detectar_usuarios_conectados(
        salida_who=salida_who,
        origenes_permitidos=origenes_permitidos,
        hora_inicio=hora_inicio,
        hora_fin=hora_fin
    )

    if registrar_alertas:
        for alerta in alertas:
            log_alarma(
                modulo="user_monitor",
                severidad="alta",
                evento=alerta["tipo"],
                detalle=alerta["detalle"],
                extra={
                    "usuario": alerta["usuario"],
                    "origen": alerta["origen"],
                    "sesion": alerta["sesion"],
                }
            )

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
