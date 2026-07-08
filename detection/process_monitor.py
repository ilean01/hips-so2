import re
from pathlib import Path

from core.hips_logger import log_alarma


PROCESOS_SOSPECHOSOS = [
    "nc",
    "netcat",
    "ncat",
    "socat",
    "xmrig",
    "miner",
    "hydra",
    "john",
    "nmap",
    "sqlmap",
]


def _convertir_float(valor: str) -> float:
    try:
        return float(valor)
    except ValueError:
        return 0.0


def _parsear_linea_ps(linea: str):
    partes = linea.split(None, 5)

    if len(partes) < 5:
        return None

    if partes[0].upper() == "PID":
        return None

    pid = partes[0]
    usuario = partes[1]
    cpu = _convertir_float(partes[2])
    memoria = _convertir_float(partes[3])
    comando = partes[4]
    argumentos = partes[5] if len(partes) > 5 else comando

    return {
        "pid": pid,
        "usuario": usuario,
        "cpu": cpu,
        "memoria": memoria,
        "comando": comando,
        "argumentos": argumentos,
        "linea": linea.strip(),
    }


def _tokens(texto: str) -> list:
    return re.findall(r"[a-zA-Z0-9_.+-]+", texto.lower())


def _coincide_proceso_sospechoso(proceso: dict, nombre_sospechoso: str) -> bool:
    comando_base = Path(proceso["comando"]).name.lower()
    texto = f"{proceso['comando']} {proceso['argumentos']}".lower()
    tokens = _tokens(texto)

    if nombre_sospechoso == comando_base:
        return True

    if nombre_sospechoso in tokens:
        return True

    if len(nombre_sospechoso) <= 2:
        return False

    patron = re.compile(
        r"(?<![a-zA-Z0-9_])" + re.escape(nombre_sospechoso) + r"(?![a-zA-Z0-9_])",
        re.IGNORECASE
    )

    return bool(patron.search(texto))


def detectar_procesos_sospechosos(
    salida_ps: str,
    cpu_umbral: float = 80.0,
    memoria_umbral: float = 80.0
) -> list[dict]:
    alertas = []

    for linea in salida_ps.splitlines():
        proceso = _parsear_linea_ps(linea)

        if proceso is None:
            continue

        for nombre in PROCESOS_SOSPECHOSOS:
            if _coincide_proceso_sospechoso(proceso, nombre):
                alertas.append({
                    "tipo": "proceso_sospechoso",
                    "pid": proceso["pid"],
                    "usuario": proceso["usuario"],
                    "comando": proceso["comando"],
                    "detalle": f"Proceso sospechoso detectado: {nombre}",
                    "proceso": proceso["linea"],
                })
                break

        if proceso["cpu"] >= cpu_umbral:
            alertas.append({
                "tipo": "cpu_alta",
                "pid": proceso["pid"],
                "usuario": proceso["usuario"],
                "comando": proceso["comando"],
                "detalle": f"Proceso con CPU alta: {proceso['cpu']}%",
                "proceso": proceso["linea"],
            })

        if proceso["memoria"] >= memoria_umbral:
            alertas.append({
                "tipo": "memoria_alta",
                "pid": proceso["pid"],
                "usuario": proceso["usuario"],
                "comando": proceso["comando"],
                "detalle": f"Proceso con memoria alta: {proceso['memoria']}%",
                "proceso": proceso["linea"],
            })

    return alertas


def analizar_procesos(
    salida_ps: str,
    cpu_umbral: float = 80.0,
    memoria_umbral: float = 80.0,
    registrar_alertas: bool = True
) -> list[dict]:
    alertas = detectar_procesos_sospechosos(
        salida_ps=salida_ps,
        cpu_umbral=cpu_umbral,
        memoria_umbral=memoria_umbral
    )

    if registrar_alertas:
        for alerta in alertas:
            log_alarma(
                modulo="process_monitor",
                severidad="alta",
                evento=alerta["tipo"],
                detalle=alerta["detalle"],
                extra={
                    "pid": alerta["pid"],
                    "usuario": alerta["usuario"],
                    "comando": alerta["comando"],
                    "proceso": alerta["proceso"],
                }
            )

    return alertas
