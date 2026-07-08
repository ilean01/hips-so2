from pathlib import Path
import subprocess

from detection.auth_failures import analizar_log_auth
from detection.cron_monitor import analizar_crontab
from detection.ddos_monitor import analizar_conexiones_red
from detection.file_integrity import cargar_baseline, verificar_integridad
from detection.mail_queue import analizar_cola_correo
from detection.process_monitor import analizar_procesos
from detection.sniffers import analizar_procesos_sniffers
from detection.system_logs import analizar_logs_sistema
from detection.tmp_monitor import escanear_tmp
from detection.user_monitor import crear_baseline_usuarios, analizar_usuarios


def ejecutar_comando(comando):
    try:
        resultado = subprocess.run(
            comando,
            text=True,
            capture_output=True,
            check=False
        )
        return resultado.stdout
    except Exception:
        return ""


def leer_texto(ruta):
    path = Path(ruta)

    if not path.exists():
        return ""

    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except PermissionError:
        return ""


def obtener_log_auth_default():
    candidatos = [
        "/var/log/secure",
        "/var/log/auth.log",
    ]

    for ruta in candidatos:
        if Path(ruta).exists():
            return ruta

    return None


def leer_cron_sistema():
    partes = []

    crontab = Path("/etc/crontab")
    if crontab.exists():
        partes.append(leer_texto(str(crontab)))

    cron_d = Path("/etc/cron.d")
    if cron_d.exists():
        for archivo in cron_d.iterdir():
            if archivo.is_file():
                partes.append(leer_texto(str(archivo)))

    return "\n".join(partes)


def cargar_baseline_archivos_default():
    ruta = Path("config/baseline_archivos.json")

    if not ruta.exists():
        return None

    return cargar_baseline(str(ruta))


def agregar_alertas(alertas_por_modulo, modulo, alertas):
    if alertas:
        alertas_por_modulo[modulo] = alertas


def ejecutar_ciclo_deteccion(entradas=None, registrar_alertas_logs=True):
    entradas = entradas or {}
    alertas_por_modulo = {}

    baseline_archivos = entradas.get("baseline_archivos")
    if baseline_archivos is None:
        baseline_archivos = cargar_baseline_archivos_default()

    if baseline_archivos:
        alertas = verificar_integridad(
            baseline_archivos,
            registrar_alertas=registrar_alertas_logs
        )
        agregar_alertas(alertas_por_modulo, "integridad_archivos", alertas)

    if "auth_log_path" in entradas:
        auth_log_path = entradas.get("auth_log_path")
    else:
        auth_log_path = obtener_log_auth_default()

    if auth_log_path:
        alertas = analizar_log_auth(
            auth_log_path,
            umbral=entradas.get("auth_umbral", 5),
            registrar_alertas=registrar_alertas_logs
        )
        agregar_alertas(alertas_por_modulo, "auth_failures", alertas)

    procesos_texto = entradas.get("procesos_texto")
    if procesos_texto is None:
        procesos_texto = ejecutar_comando([
            "ps",
            "-eo",
            "pid,user,%cpu,%mem,comm,args",
            "--no-headers"
        ])

    alertas = analizar_procesos(
        procesos_texto,
        cpu_umbral=entradas.get("cpu_umbral", 80.0),
        memoria_umbral=entradas.get("memoria_umbral", 80.0),
        registrar_alertas=registrar_alertas_logs
    )
    agregar_alertas(alertas_por_modulo, "process_monitor", alertas)

    alertas = analizar_procesos_sniffers(
        procesos_texto,
        registrar_alertas=registrar_alertas_logs
    )
    agregar_alertas(alertas_por_modulo, "sniffers", alertas)

    passwd_actual = entradas.get("passwd_actual")
    if passwd_actual is None:
        passwd_actual = leer_texto("/etc/passwd")

    baseline_usuarios = entradas.get("baseline_usuarios")
    if baseline_usuarios is None:
        baseline_usuarios = crear_baseline_usuarios(passwd_actual)

    if passwd_actual and baseline_usuarios:
        alertas = analizar_usuarios(
            baseline_usuarios,
            passwd_actual,
            registrar_alertas=registrar_alertas_logs
        )
        agregar_alertas(alertas_por_modulo, "user_monitor", alertas)

    system_logs_texto = entradas.get("system_logs_texto")
    if system_logs_texto is None:
        system_logs_texto = ejecutar_comando([
            "journalctl",
            "-n",
            "200",
            "--no-pager"
        ])

    alertas = analizar_logs_sistema(
        system_logs_texto,
        registrar_alertas=registrar_alertas_logs
    )
    agregar_alertas(alertas_por_modulo, "system_logs", alertas)

    tmp_path = entradas.get("tmp_path", "/tmp")
    if Path(tmp_path).exists():
        alertas = escanear_tmp(
            tmp_path,
            registrar_alertas=registrar_alertas_logs
        )
        agregar_alertas(alertas_por_modulo, "tmp_monitor", alertas)

    crontab_texto = entradas.get("crontab_texto")
    if crontab_texto is None:
        crontab_texto = leer_cron_sistema()

    alertas = analizar_crontab(
        crontab_texto,
        registrar_alertas=registrar_alertas_logs
    )
    agregar_alertas(alertas_por_modulo, "cron_monitor", alertas)

    mailq_texto = entradas.get("mailq_texto")
    if mailq_texto is None:
        mailq_texto = ejecutar_comando(["mailq"])

    alertas = analizar_cola_correo(
        mailq_texto,
        umbral_cola=entradas.get("mailq_umbral", 20),
        registrar_alertas=registrar_alertas_logs
    )
    agregar_alertas(alertas_por_modulo, "mail_queue", alertas)

    conexiones_texto = entradas.get("conexiones_texto")
    if conexiones_texto is None:
        conexiones_texto = ejecutar_comando(["ss", "-tun"])

    alertas = analizar_conexiones_red(
        conexiones_texto,
        umbral_conexiones=entradas.get("ddos_umbral_conexiones", 50),
        umbral_syn=entradas.get("ddos_umbral_syn", 20),
        registrar_alertas=registrar_alertas_logs
    )
    agregar_alertas(alertas_por_modulo, "ddos_monitor", alertas)

    return alertas_por_modulo
