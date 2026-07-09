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

        if tipo in {"correo_diferido", "error_conexion_correo", "rebote_correo"}:
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
