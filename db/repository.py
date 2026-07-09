import json


def buscar_alarma_pendiente_duplicada(
    conexion,
    tipo_alarma: str,
    modulo: str,
    descripcion: str,
    ip_origen=None,
):
    sql = """
    SELECT id
    FROM alarmas
    WHERE tipo_alarma = %s
      AND modulo = %s
      AND COALESCE(ip_origen, '') = COALESCE(%s, '')
      AND COALESCE(descripcion, '') = COALESCE(%s, '')
      AND resuelta = false
    ORDER BY id DESC
    LIMIT 1;
    """

    with conexion.cursor() as cursor:
        cursor.execute(sql, (tipo_alarma, modulo, ip_origen, descripcion))
        fila = cursor.fetchone()

    if fila:
        return fila[0]

    return None


def insertar_alarma(
    conexion,
    tipo_alarma: str,
    modulo: str,
    descripcion: str,
    severidad: str = "MEDIA",
    ip_origen=None,
    resuelta: bool = False
) -> int:
    if not resuelta:
        alarma_existente = buscar_alarma_pendiente_duplicada(
            conexion,
            tipo_alarma=tipo_alarma,
            modulo=modulo,
            descripcion=descripcion,
            ip_origen=ip_origen,
        )

        if alarma_existente is not None:
            return alarma_existente

    sql = """
    INSERT INTO alarmas (tipo_alarma, ip_origen, modulo, descripcion, severidad, resuelta)
    VALUES (%s, %s, %s, %s, %s, %s)
    RETURNING id;
    """

    with conexion.cursor() as cursor:
        cursor.execute(
            sql,
            (tipo_alarma, ip_origen, modulo, descripcion, severidad, resuelta)
        )
        alarma_id = cursor.fetchone()[0]

    conexion.commit()
    return alarma_id


def insertar_evento_sistema(
    conexion,
    modulo: str,
    evento: str,
    detalle: str
) -> int:
    sql = """
    INSERT INTO eventos_sistema (modulo, evento, detalle)
    VALUES (%s, %s, %s)
    RETURNING id;
    """

    with conexion.cursor() as cursor:
        cursor.execute(sql, (modulo, evento, detalle))
        evento_id = cursor.fetchone()[0]

    conexion.commit()
    return evento_id


def insertar_accion_prevencion(
    conexion,
    alarma_id: int,
    accion: str,
    resultado: str,
    detalle: str = ""
) -> int:
    sql = """
    INSERT INTO acciones_prevencion (alarma_id, accion, resultado, detalle)
    VALUES (%s, %s, %s, %s)
    RETURNING id;
    """

    with conexion.cursor() as cursor:
        cursor.execute(sql, (alarma_id, accion, resultado, detalle))
        accion_id = cursor.fetchone()[0]

    conexion.commit()
    return accion_id


def obtener_configuracion_modulos(conexion) -> list:
    sql = """
    SELECT modulo, habilitado, intervalo_segundos, umbral, configuracion
    FROM configuracion_modulos
    ORDER BY id;
    """

    with conexion.cursor() as cursor:
        cursor.execute(sql)
        filas = cursor.fetchall()

    configuraciones = []

    for fila in filas:
        modulo, habilitado, intervalo_segundos, umbral, configuracion = fila

        if isinstance(configuracion, str):
            configuracion = json.loads(configuracion)

        configuraciones.append({
            "modulo": modulo,
            "habilitado": habilitado,
            "intervalo_segundos": intervalo_segundos,
            "umbral": umbral,
            "configuracion": configuracion,
        })

    return configuraciones
