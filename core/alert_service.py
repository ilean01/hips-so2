import json

from db.repository import insertar_alarma, insertar_evento_sistema


MAPA_SEVERIDAD = {
    "critica": "CRITICA",
    "crítica": "CRITICA",
    "alta": "ALTA",
    "media": "MEDIA",
    "baja": "BAJA",
    "CRITICA": "CRITICA",
    "ALTA": "ALTA",
    "MEDIA": "MEDIA",
    "BAJA": "BAJA",
}


def normalizar_severidad(severidad):
    if severidad is None:
        return "MEDIA"

    texto = str(severidad).strip()

    return MAPA_SEVERIDAD.get(texto, MAPA_SEVERIDAD.get(texto.lower(), "MEDIA"))


def extraer_ip_origen(alerta):
    if "ip_origen" in alerta:
        return alerta["ip_origen"]

    if "ip" in alerta:
        return alerta["ip"]

    extra = alerta.get("extra")

    if isinstance(extra, dict):
        if "ip_origen" in extra:
            return extra["ip_origen"]
        if "ip" in extra:
            return extra["ip"]

    return None


def construir_descripcion(alerta):
    detalle = alerta.get("detalle") or alerta.get("descripcion") or "Alerta generada por el HIPS"

    extra = alerta.get("extra")

    if extra:
        return f"{detalle} | extra={json.dumps(extra, ensure_ascii=False)}"

    return detalle


def evento_alerta_ya_registrado(conexion, modulo, detalle):
    sql = """
    SELECT id
    FROM eventos_sistema
    WHERE modulo = %s
      AND evento = 'alerta_registrada'
      AND detalle = %s
    LIMIT 1;
    """

    with conexion.cursor() as cursor:
        cursor.execute(sql, (modulo, detalle))
        return cursor.fetchone() is not None


def registrar_alerta_db(conexion, modulo, alerta):
    tipo_alarma = alerta.get("tipo") or alerta.get("evento") or "alerta_generica"
    severidad = normalizar_severidad(alerta.get("severidad"))
    descripcion = construir_descripcion(alerta)
    ip_origen = extraer_ip_origen(alerta)

    alarma_id = insertar_alarma(
        conexion,
        tipo_alarma=tipo_alarma,
        modulo=modulo,
        descripcion=descripcion,
        severidad=severidad,
        ip_origen=ip_origen,
        resuelta=False
    )

    detalle_evento = f"Se registró alerta {tipo_alarma} con id {alarma_id}"

    if not evento_alerta_ya_registrado(conexion, modulo, detalle_evento):
        insertar_evento_sistema(
            conexion,
            modulo=modulo,
            evento="alerta_registrada",
            detalle=detalle_evento
        )

    return alarma_id


def registrar_alertas_db(conexion, modulo, alertas):
    ids = []

    for alerta in alertas:
        ids.append(registrar_alerta_db(conexion, modulo, alerta))

    return ids
