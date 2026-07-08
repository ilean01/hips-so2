import os
import re

from prevention.actions import bloquear_ip, finalizar_proceso, cuarentenar_archivo


IPS_NO_BLOQUEAR = {
    "",
    "N/A",
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

    if modulo == "sniffers":
        pid = extraer_pid(alerta)
        if pid and pid != os.getpid():
            return finalizar_proceso(pid, dry_run=dry_run)

    if modulo == "process_monitor":
        pid = extraer_pid(alerta)
        if pid and pid != os.getpid():
            return finalizar_proceso(pid, dry_run=dry_run)

    if modulo in {"ddos_monitor", "auth_failures", "system_logs", "mail_queue"}:
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

    for modulo, alertas in alertas_por_modulo.items():
        for alerta in alertas:
            try:
                accion = prevenir_alerta(modulo, alerta, dry_run=dry_run)
            except Exception as error:
                accion = {
                    "accion": "error_prevencion",
                    "modulo": modulo,
                    "tipo": alerta.get("tipo", "desconocida"),
                    "dry_run": dry_run,
                    "ejecutado": False,
                    "error": str(error),
                }

            acciones.append({
                "modulo": modulo,
                "tipo": alerta.get("tipo", "desconocida"),
                "accion": accion,
            })

    return {
        "dry_run": dry_run,
        "total_acciones": len(acciones),
        "acciones": acciones,
    }


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

    acciones_por_modulo = {}
    for item in resultado_prevencion.get("acciones", []):
        modulo = item.get("modulo")
        accion = item.get("accion", {})

        if accion.get("ejecutado") is True:
            acciones_por_modulo.setdefault(modulo, 0)
            acciones_por_modulo[modulo] += 1

    ids_a_resolver = []

    for modulo, cantidad_acciones in acciones_por_modulo.items():
        ids_modulo = persistencia.get(modulo, {}).get("ids", [])
        ids_a_resolver.extend(ids_modulo[:cantidad_acciones])

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
