import json
import os
import re

from prevention.actions import (
    bloquear_ip,
    finalizar_proceso,
    cuarentenar_archivo,
    bloquear_usuario,
    cambiar_password_usuario,
    reiniciar_postfix,
    pausar_postfix,
    limpiar_cola_correo,
    documentar_integridad_archivo,
    desactivar_modo_promiscuo,
)


IPS_NO_BLOQUEAR = {
    "",
    "N/A",
    "sin_ip",
    "unknown",
    "desconocida",
    "127.0.0.1",
    "::1",
    "localhost",
}


def _extra(alerta):
    extra = alerta.get("extra")
    if isinstance(extra, dict):
        return extra
    return {}


def _obtener_valor(alerta, claves):
    extra = _extra(alerta)

    for clave in claves:
        if clave in alerta and alerta[clave] not in (None, ""):
            return alerta[clave]

    for clave in claves:
        if clave in extra and extra[clave] not in (None, ""):
            return extra[clave]

    return None


def extraer_pid(alerta):
    valor = _obtener_valor(alerta, ["pid", "proceso_pid"])
    if valor is not None:
        try:
            return int(valor)
        except ValueError:
            return None

    texto = " ".join([
        str(alerta.get("proceso", "")),
        str(alerta.get("linea", "")),
        str(alerta.get("detalle", "")),
        str(alerta.get("descripcion", "")),
    ])

    match_inicio = re.match(r"^\s*(\d+)\s+", texto)
    if match_inicio:
        return int(match_inicio.group(1))

    match_pid = re.search(r"\bpid\s*[=:]?\s*(\d+)\b", texto, re.IGNORECASE)
    if match_pid:
        return int(match_pid.group(1))

    return None


def extraer_archivo(alerta):
    valor = _obtener_valor(alerta, ["archivo", "ruta", "ruta_archivo", "path"])
    if valor:
        return str(valor)

    texto = " ".join([
        str(alerta.get("detalle", "")),
        str(alerta.get("descripcion", "")),
        str(alerta.get("proceso", "")),
    ])

    match_tmp = re.search(r"(/tmp/[^\s,;]+)", texto)
    if match_tmp:
        return match_tmp.group(1).strip()

    match_cron = re.search(r"(/etc/cron\.d/[^\s,;]+|/var/spool/cron/[^\s,;]+)", texto)
    if match_cron:
        return match_cron.group(1).strip()

    match_etc = re.search(r"(/etc/[^\s,;]+)", texto)
    if match_etc:
        return match_etc.group(1).strip()

    return None


def extraer_ip(alerta):
    valor = _obtener_valor(alerta, ["ip", "ip_origen", "origen", "remote_ip"])
    if valor:
        ip = str(valor).strip()
    else:
        texto = " ".join([
            str(alerta.get("detalle", "")),
            str(alerta.get("descripcion", "")),
        ])
        match_ip = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", texto)
        ip = match_ip.group(0) if match_ip else ""

    if ip in IPS_NO_BLOQUEAR:
        return None

    return ip


def extraer_usuario(alerta):
    valor = _obtener_valor(alerta, ["usuario", "user", "username"])
    if valor:
        return str(valor).strip()

    texto = " ".join([
        str(alerta.get("detalle", "")),
        str(alerta.get("descripcion", "")),
    ])

    match_usuario = re.search(r"usuario\s+([a-z_][a-z0-9_-]*\$?)", texto, re.IGNORECASE)
    if match_usuario:
        return match_usuario.group(1)

    return None


def extraer_interfaz(alerta):
    valor = _obtener_valor(alerta, ["interfaz", "interface", "iface"])
    if valor:
        return str(valor).strip()

    texto = " ".join([
        str(alerta.get("detalle", "")),
        str(alerta.get("descripcion", "")),
        str(alerta.get("linea", "")),
    ])

    match = re.search(
        r"interfaz\s+(?:en modo promiscuo\s+)?(?:detectada:\s*)?([a-zA-Z0-9_.:-]+)",
        texto,
        re.IGNORECASE
    )

    if match:
        return match.group(1)

    return None


def prevenir_alerta(modulo, alerta, dry_run=True):
    tipo = alerta.get("tipo", "desconocida")

    if modulo == "tmp_monitor":
        archivo = extraer_archivo(alerta)
        if archivo:
            return cuarentenar_archivo(archivo, dry_run=dry_run)

    if modulo == "cron_monitor":
        archivo = extraer_archivo(alerta)
        if archivo:
            return cuarentenar_archivo(archivo, dry_run=dry_run)

    if modulo == "integridad_archivos":
        archivo = extraer_archivo(alerta)
        if archivo:
            return documentar_integridad_archivo(
                archivo,
                motivo=alerta.get("detalle", tipo),
                dry_run=dry_run
            )

    if modulo == "sniffers":
        if tipo == "interfaz_promiscua":
            interfaz = extraer_interfaz(alerta)
            if interfaz:
                return desactivar_modo_promiscuo(interfaz, dry_run=dry_run)

        pid = extraer_pid(alerta)
        if pid and pid != os.getpid():
            return finalizar_proceso(pid, dry_run=dry_run)

    if modulo == "process_monitor":
        pid = extraer_pid(alerta)
        if pid and pid != os.getpid():
            return finalizar_proceso(pid, dry_run=dry_run)

    if modulo == "user_monitor":
        usuario = extraer_usuario(alerta)

        if usuario and tipo in {
            "usuario_nuevo",
            "usuario_eliminado",
        }:
            return {
                "accion": "revision_manual_usuario",
                "modulo": modulo,
                "tipo": tipo,
                "usuario": usuario,
                "dry_run": dry_run,
                "ejecutado": False,
                "motivo": "Cambio de usuario detectado; requiere revision humana",
            }

        if usuario and tipo in {
            "usuario_uid_0",
            "uid_modificado",
            "shell_interactiva_agregada",
            "origen_login_inusual",
            "login_fuera_horario",
        }:
            return bloquear_usuario(usuario, dry_run=dry_run)

        if usuario and tipo == "credenciales_comprometidas":
            return cambiar_password_usuario(usuario, dry_run=dry_run)

    if modulo == "mail_queue":
        if tipo == "cola_correo_alta":
            return limpiar_cola_correo(dry_run=dry_run)

        if tipo in {"correo_diferido",
            "envio_masivo_correo", "error_conexion_correo", "rebote_correo"}:
            return reiniciar_postfix(dry_run=dry_run)

        if tipo == "posible_spam_correo":
            return pausar_postfix(dry_run=dry_run)

    if modulo in {"ddos_monitor", "auth_failures", "system_logs"}:
        ip = extraer_ip(alerta)
        if ip:
            return bloquear_ip(ip, dry_run=dry_run)

    return {
        "accion": "sin_accion_automatica",
        "modulo": modulo,
        "tipo": tipo,
        "dry_run": dry_run,
        "ejecutado": False,
        "motivo": "No se encontró dato suficiente para ejecutar prevención automática",
    }


def prevenir_alertas(alertas_por_modulo, dry_run=True):
    acciones = []
    archivos_prevenidos = {}

    for modulo, alertas in alertas_por_modulo.items():
        for alerta in alertas:
            tipo = alerta.get("tipo", "desconocida")
            archivo = extraer_archivo(alerta)

            if modulo in {"tmp_monitor", "cron_monitor"} and archivo in archivos_prevenidos:
                accion = {
                    "accion": "archivo_ya_prevenido",
                    "archivo": archivo,
                    "dry_run": dry_run,
                    "ejecutado": True,
                    "motivo": "El archivo ya fue tratado por otra alerta del mismo ciclo",
                    "accion_original": archivos_prevenidos[archivo],
                }
            else:
                try:
                    accion = prevenir_alerta(modulo, alerta, dry_run=dry_run)
                except Exception as error:
                    accion = {
                        "accion": "error_prevencion",
                        "modulo": modulo,
                        "tipo": tipo,
                        "dry_run": dry_run,
                        "ejecutado": False,
                        "error": str(error),
                    }

                if (
                    modulo in {"tmp_monitor", "cron_monitor"}
                    and archivo
                    and accion.get("ejecutado") is True
                ):
                    archivos_prevenidos[archivo] = accion.get("accion", "prevencion_ejecutada")

            acciones.append({
                "modulo": modulo,
                "tipo": tipo,
                "accion": accion,
            })

    return {
        "dry_run": dry_run,
        "total_acciones": len(acciones),
        "acciones": acciones,
    }


def _acciones_con_alarmas(persistencia: dict, resultado_prevencion: dict):
    indices_por_modulo = {}

    for item in resultado_prevencion.get("acciones", []):
        modulo = item.get("modulo")
        accion = item.get("accion", {})

        indice = indices_por_modulo.get(modulo, 0)
        indices_por_modulo[modulo] = indice + 1

        ids_modulo = persistencia.get(modulo, {}).get("ids", []) if persistencia else []
        alarma_id = ids_modulo[indice] if indice < len(ids_modulo) else None

        yield alarma_id, modulo, item.get("tipo", "desconocida"), accion


def marcar_alarmas_prevenidas_resueltas(conexion, persistencia: dict, resultado_prevencion: dict) -> dict:
    if conexion is None:
        return {
            "actualizadas": 0,
            "ids": [],
            "motivo": "sin_conexion"
        }

    if not persistencia or not resultado_prevencion:
        return {
            "actualizadas": 0,
            "ids": [],
            "motivo": "sin_datos"
        }

    ids_a_resolver = []

    for alarma_id, _modulo, _tipo, accion in _acciones_con_alarmas(persistencia, resultado_prevencion):
        if alarma_id is not None and accion.get("ejecutado") is True:
            ids_a_resolver.append(alarma_id)

    if not ids_a_resolver:
        return {
            "actualizadas": 0,
            "ids": [],
            "motivo": "sin_acciones_ejecutadas"
        }

    cur = conexion.cursor()

    cur.execute("""
        UPDATE alarmas
        SET resuelta = true
        WHERE id = ANY(%s)
        RETURNING id;
    """, (ids_a_resolver,))

    ids_actualizadas = [fila[0] for fila in cur.fetchall()]

    for alarma_id in ids_actualizadas:
        cur.execute("""
            INSERT INTO eventos_sistema (modulo, evento, detalle)
            VALUES (%s, %s, %s);
        """, (
            "prevention_engine",
            "alarma_resuelta_automaticamente",
            f"Alarma {alarma_id} marcada como resuelta automáticamente por prevención"
        ))

    conexion.commit()
    cur.close()

    return {
        "actualizadas": len(ids_actualizadas),
        "ids": ids_actualizadas,
        "motivo": "prevencion_ejecutada"
    }



def registrar_acciones_prevencion_db(conexion, persistencia: dict, resultado_prevencion: dict) -> dict:
    if conexion is None:
        return {
            "cantidad": 0,
            "ids": [],
            "motivo": "sin_conexion"
        }

    if not persistencia or not resultado_prevencion:
        return {
            "cantidad": 0,
            "ids": [],
            "motivo": "sin_datos"
        }

    ids_insertados = []
    cur = conexion.cursor()

    for alarma_id, modulo, tipo, accion in _acciones_con_alarmas(persistencia, resultado_prevencion):
        if alarma_id is None:
            continue

        nombre_accion = accion.get("accion", "desconocida")

        if nombre_accion == "error_prevencion":
            resultado = "error"
        elif accion.get("ejecutado") is True:
            resultado = "ejecutado"
        else:
            resultado = "no_ejecutado"

        detalle = json.dumps({
            "modulo": modulo,
            "tipo": tipo,
            "accion": accion,
        }, ensure_ascii=False)

        cur.execute("""
            SELECT id
            FROM acciones_prevencion
            WHERE alarma_id = %s
              AND accion = %s
              AND resultado = %s
            LIMIT 1;
        """, (
            alarma_id,
            nombre_accion,
            resultado
        ))

        if cur.fetchone():
            continue

        cur.execute("""
            INSERT INTO acciones_prevencion (alarma_id, accion, resultado, detalle)
            VALUES (%s, %s, %s, %s)
            RETURNING id;
        """, (
            alarma_id,
            nombre_accion,
            resultado,
            detalle
        ))

        ids_insertados.append(cur.fetchone()[0])

    conexion.commit()
    cur.close()

    return {
        "cantidad": len(ids_insertados),
        "ids": ids_insertados,
        "motivo": "acciones_registradas"
    }


# HIPS_CAMBIAR_PASSWORD_USUARIO_WRAPPER
import re as _hips_re_cambiar_password
import secrets as _hips_secrets_password
import string as _hips_string_password
import subprocess as _hips_subprocess_password


def _hips_extraer_usuario_para_password(alerta: dict):
    for clave in ("usuario", "user", "username", "usuario_afectado"):
        valor = alerta.get(clave)
        if valor:
            return str(valor).strip()

    texto = " ".join(
        str(alerta.get(clave, ""))
        for clave in ("detalle", "descripcion", "linea", "mensaje")
    )

    match = _hips_re_cambiar_password.search(
        r"(?:usuario|user|cuenta)(?:\s*[=:]\s*|\s+)([a-zA-Z_][a-zA-Z0-9_-]{0,31})",
        texto,
        _hips_re_cambiar_password.IGNORECASE
    )

    if match:
        return match.group(1).strip()

    return None


def _hips_generar_password_temporal():
    alfabeto = _hips_string_password.ascii_letters + _hips_string_password.digits
    parte = "".join(_hips_secrets_password.choice(alfabeto) for _ in range(14))
    return "HipsTemp_" + parte + "!"


def _hips_cambiar_password_usuario(alerta: dict, *args, **kwargs):
    dry_run = bool(kwargs.get("dry_run", False))
    usuario = _hips_extraer_usuario_para_password(alerta)

    protegidos = {
        "root",
        "ile",
        "postgres",
        "apache",
        "nginx",
        "postfix",
        "nobody",
        "dbus",
        "systemd-network",
        "systemd-resolve",
    }

    if not usuario:
        return {
            "accion": "sin_accion_automatica",
            "modulo": alerta.get("modulo"),
            "tipo": alerta.get("tipo") or alerta.get("tipo_alarma"),
            "dry_run": dry_run,
            "ejecutado": False,
            "motivo": "No se encontró usuario para cambiar contraseña",
        }

    if usuario in protegidos:
        return {
            "accion": "cambiar_password_usuario",
            "usuario": usuario,
            "dry_run": dry_run,
            "ejecutado": False,
            "motivo": "Usuario protegido: no se cambia contraseña automáticamente",
        }

    password_temporal = _hips_generar_password_temporal()

    if dry_run:
        return {
            "accion": "cambiar_password_usuario",
            "usuario": usuario,
            "dry_run": True,
            "ejecutado": False,
            "motivo": "dry_run activo",
        }

    _hips_subprocess_password.run(
        ["sudo", "chpasswd"],
        input=f"{usuario}:{password_temporal}\n",
        text=True,
        check=True,
    )

    return {
        "accion": "cambiar_password_usuario",
        "usuario": usuario,
        "dry_run": False,
        "ejecutado": True,
        "comandos": ["sudo chpasswd"],
        "password_temporal": "generada_no_mostrada",
    }


def _hips_wrapper_password(original_func):
    def wrapper(alerta, *args, **kwargs):
        if isinstance(alerta, dict):
            tipo = str(alerta.get("tipo") or alerta.get("tipo_alarma") or "")
            if tipo in {
                "password_comprometida",
                "credencial_comprometida",
                "cambio_password_usuario",
            }:
                return _hips_cambiar_password_usuario(alerta, *args, **kwargs)

        return original_func(alerta, *args, **kwargs)

    return wrapper


for _hips_nombre_funcion in list(globals()):
    if _hips_nombre_funcion.startswith("_"):
        continue

    if "preven" not in _hips_nombre_funcion and "accion" not in _hips_nombre_funcion:
        continue

    _hips_funcion = globals().get(_hips_nombre_funcion)

    if callable(_hips_funcion):
        globals()[_hips_nombre_funcion] = _hips_wrapper_password(_hips_funcion)


# HIPS_CAMBIAR_PASSWORD_USUARIO_WRAPPER_FINAL_INTERNO
def _hips_wrapper_password_final_interno(original_func):
    def wrapper(*args, **kwargs):
        alerta = None

        if args and isinstance(args[0], dict):
            alerta = args[0]
        elif "alerta" in kwargs and isinstance(kwargs["alerta"], dict):
            alerta = kwargs["alerta"]

        if alerta:
            tipo = str(alerta.get("tipo") or alerta.get("tipo_alarma") or "")
            modulo = str(alerta.get("modulo") or "")

            if tipo in {
                "password_comprometida",
                "credencial_comprometida",
                "cambio_password_usuario",
            }:
                return _hips_cambiar_password_usuario(alerta, *args[1:], **kwargs)

        return original_func(*args, **kwargs)

    wrapper.__name__ = getattr(original_func, "__name__", "wrapper")
    return wrapper


for _hips_nombre_funcion_final, _hips_funcion_final in list(globals().items()):
    if not callable(_hips_funcion_final):
        continue

    if _hips_nombre_funcion_final.startswith("_hips_"):
        continue

    if _hips_nombre_funcion_final in {
        "_hips_cambiar_password_usuario",
        "_hips_extraer_usuario_para_password",
        "_hips_generar_password_temporal",
    }:
        continue

    nombre_bajo = _hips_nombre_funcion_final.lower()

    if (
        "preven" in nombre_bajo
        or "accion" in nombre_bajo
        or "ejecut" in nombre_bajo
        or "resolver" in nombre_bajo
        or "aplicar" in nombre_bajo
        or "manejar" in nombre_bajo
    ):
        globals()[_hips_nombre_funcion_final] = _hips_wrapper_password_final_interno(_hips_funcion_final)


# HIPS_OVERRIDE_PREVENIR_ALERTA_PASSWORD_COMPROMETIDA
_hips_prevenir_alerta_original_password_comprometida = prevenir_alerta

def prevenir_alerta(modulo, alerta, dry_run=True):
    tipo = ""

    if isinstance(alerta, dict):
        tipo = str(alerta.get("tipo") or alerta.get("tipo_alarma") or "")

    if modulo == "system_logs" and tipo in {
        "password_comprometida",
        "credencial_comprometida",
        "cambio_password_usuario",
    }:
        return _hips_cambiar_password_usuario(alerta, dry_run=dry_run)

    return _hips_prevenir_alerta_original_password_comprometida(
        modulo,
        alerta,
        dry_run=dry_run
    )


# HIPS_MAIL_QUEUE_BLOQUEAR_USUARIO_GENERADOR
_hips_prevenir_alerta_original_mail_queue_usuario = prevenir_alerta

def prevenir_alerta(modulo, alerta, dry_run=True):
    tipo = ""

    if isinstance(alerta, dict):
        tipo = str(alerta.get("tipo") or alerta.get("tipo_alarma") or "")

    if modulo == "mail_queue" and tipo == "envio_masivo_correo":
        usuario = alerta.get("usuario") if isinstance(alerta, dict) else None

        protegidos = {
            "root",
            "ile",
            "postgres",
            "apache",
            "nginx",
            "postfix",
            "nobody",
            "dbus",
            "systemd-network",
            "systemd-resolve",
        }

        if usuario and usuario not in protegidos:
            return bloquear_usuario(usuario, dry_run=dry_run)

    return _hips_prevenir_alerta_original_mail_queue_usuario(
        modulo,
        alerta,
        dry_run=dry_run
    )


# HIPS_EMAIL_POR_ACCION_PREVENCION_WRAPPER
import os as _hips_os_email_prev
import json as _hips_json_email_prev
import socket as _hips_socket_email_prev
import subprocess as _hips_subprocess_email_prev
from datetime import datetime as _hips_datetime_email_prev
from pathlib import Path as _hips_Path_email_prev

_hips_prevenir_alerta_original_email_prev = prevenir_alerta

def _hips_admins_email_prevencion():
    raw = _hips_os_email_prev.environ.get("HIPS_ADMIN_EMAIL", "").strip()

    if not raw:
        env_path = _hips_Path_email_prev("/etc/hips/hips.env")
        if env_path.exists():
            try:
                for line in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                    if line.startswith("HIPS_ADMIN_EMAIL="):
                        raw = line.split("=", 1)[1].strip().strip('"').strip("'")
                        break
            except Exception:
                raw = ""

    admins = [x.strip() for x in raw.replace(";", ",").split(",") if x.strip()]
    return admins


def _hips_alerta_valor_email_prev(alerta, clave, defecto=""):
    if isinstance(alerta, dict):
        return alerta.get(clave, defecto)
    return getattr(alerta, clave, defecto)


def _hips_enviar_email_accion_prevencion(modulo, alerta, accion):
    try:
        if not isinstance(accion, dict):
            return

        if accion.get("dry_run") is True:
            return

        if accion.get("ejecutado") is not True:
            return

        accion_nombre = accion.get("accion", "accion_preventiva")

        if accion_nombre in ("sin_accion_automatica", "error_prevencion"):
            return

        admins = _hips_admins_email_prevencion()
        if not admins:
            return

        sendmail_path = "/usr/sbin/sendmail"
        if not _hips_Path_email_prev(sendmail_path).exists():
            sendmail_path = "/usr/lib/sendmail"

        if not _hips_Path_email_prev(sendmail_path).exists():
            return

        tipo = _hips_alerta_valor_email_prev(alerta, "tipo", "")
        if not tipo:
            tipo = _hips_alerta_valor_email_prev(alerta, "tipo_alarma", "")

        descripcion = _hips_alerta_valor_email_prev(alerta, "descripcion", "")
        if not descripcion:
            descripcion = _hips_alerta_valor_email_prev(alerta, "detalle", "")

        ip = accion.get("ip") or accion.get("ip_origen") or _hips_alerta_valor_email_prev(alerta, "ip_origen", "")
        usuario = accion.get("usuario") or _hips_alerta_valor_email_prev(alerta, "usuario", "")
        comandos = accion.get("comandos", [])

        host = _hips_socket_email_prev.getfqdn()
        ahora = _hips_datetime_email_prev.now().strftime("%Y-%m-%d %H:%M:%S")

        cuerpo = [
            "Accion preventiva ejecutada por HIPS",
            "",
            f"Fecha/hora: {ahora}",
            f"Host: {host}",
            f"Modulo: {modulo}",
            f"Tipo de alarma: {tipo}",
            f"Accion preventiva: {accion_nombre}",
            "Resultado: ejecutado",
        ]

        if ip:
            cuerpo.append(f"IP: {ip}")

        if usuario:
            cuerpo.append(f"Usuario: {usuario}")

        if descripcion:
            cuerpo.extend(["", "Descripcion de la alarma:", str(descripcion)])

        if comandos:
            cuerpo.extend(["", "Comandos ejecutados:"])
            for cmd in comandos:
                cuerpo.append(f"- {cmd}")

        cuerpo.extend([
            "",
            "Detalle tecnico:",
            _hips_json_email_prev.dumps(accion, ensure_ascii=False)
        ])

        mensaje = (
            "From: hips@localhost\n"
            f"To: {', '.join(admins)}\n"
            f"Subject: [HIPS PREVENCION] {accion_nombre} ejecutada en {host}\n"
            "Content-Type: text/plain; charset=UTF-8\n"
            "\n"
            + "\n".join(cuerpo)
            + "\n"
        )

        r = _hips_subprocess_email_prev.run(
            [sendmail_path, "-t"],
            input=mensaje,
            text=True,
            capture_output=True,
            timeout=15
        )

        log_dir = _hips_Path_email_prev("/var/log/hips")
        log_dir.mkdir(parents=True, exist_ok=True)

        with open("/var/log/hips/prevencion_email.log", "a", encoding="utf-8") as f:
            f.write(_hips_json_email_prev.dumps({
                "timestamp": _hips_datetime_email_prev.now().isoformat(),
                "evento": "email_accion_prevencion",
                "accion": accion_nombre,
                "modulo": modulo,
                "tipo": tipo,
                "ip": ip,
                "admins": admins,
                "returncode": r.returncode,
                "stderr": r.stderr,
            }, ensure_ascii=False) + "\n")

    except Exception as exc:
        try:
            _hips_Path_email_prev("/var/log/hips").mkdir(parents=True, exist_ok=True)
            with open("/var/log/hips/prevencion_email.log", "a", encoding="utf-8") as f:
                f.write(_hips_json_email_prev.dumps({
                    "timestamp": _hips_datetime_email_prev.now().isoformat(),
                    "evento": "error_email_accion_prevencion",
                    "error": str(exc),
                }, ensure_ascii=False) + "\n")
        except Exception:
            pass


def prevenir_alerta(modulo, alerta, dry_run=True, *args, **kwargs):
    accion = _hips_prevenir_alerta_original_email_prev(
        modulo,
        alerta,
        dry_run=dry_run,
        *args,
        **kwargs
    )

    _hips_enviar_email_accion_prevencion(modulo, alerta, accion)

    return accion
