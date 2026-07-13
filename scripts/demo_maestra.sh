#!/usr/bin/env bash
#
# DEMO MAESTRA HIPS - TODAS las pruebas reales, en el orden exacto que ya
# validaste a mano. No se saco ni se inventa ningun comando: es tu propio
# checklist, con narracion paso a paso, sleeps entre pruebas, y activando
# el HIPS manualmente (python3 hips.py) despues de cada ataque simulado
# en vez de esperar al timer.
#
# Uso:
#   chmod +x scripts/demo_maestra.sh
#   ./scripts/demo_maestra.sh
#
# Requisitos: correrlo como tu usuario 'ile' con sudo disponible, con
# postgres, postfix y el proyecto en /home/ile/hips-so2 (ajustable abajo).

set -uo pipefail

PROY="${HIPS_PROYECTO_DIR:-/home/ile/hips-so2}"
SLEEP_ENTRE_PRUEBAS="${SLEEP_ENTRE_PRUEBAS:-5}"

cd "$PROY" || { echo "No encuentro el proyecto en $PROY. Ajusta HIPS_PROYECTO_DIR."; exit 1; }

# ======================= HELPERS =======================
linea()  { echo "=================================================================="; }
paso()   { echo; linea; echo ">> $1"; linea; }
sub()    { echo; echo "-- $1"; }
pausa()  { echo "   (pausa de ${SLEEP_ENTRE_PRUEBAS}s)"; sleep "$SLEEP_ENTRE_PRUEBAS"; }

echo "Obteniendo password real de la base desde /etc/hips/hips.env ..."
DB_PASSWORD="$(sudo grep '^HIPS_DB_PASSWORD=' /etc/hips/hips.env | cut -d= -f2-)"
echo "Password obtenida (no se muestra en pantalla)."

ciclo_hips() {
    # Corre UN ciclo completo del HIPS con guardado en DB + prevencion + JSON,
    # exactamente como en tus pruebas reales.
    sub "Activando manualmente un ciclo del HIPS (guardar-db + prevenir + json)"
    sudo env HIPS_DB_NAME="hips_db" HIPS_DB_USER="hips_app" HIPS_DB_PASSWORD="$DB_PASSWORD" \
        HIPS_DB_HOST="127.0.0.1" HIPS_ADMIN_EMAIL="ile" \
        HIPS_SENDMAIL_PATH="/usr/sbin/sendmail" PYTHONPATH="$PWD" \
        python3 hips.py --guardar-db --prevenir --json
}

ciclo_hips_sin_prevenir() {
    sub "Activando manualmente un ciclo del HIPS (guardar-db + json, sin prevencion)"
    sudo env HIPS_DB_NAME="hips_db" HIPS_DB_USER="hips_app" HIPS_DB_PASSWORD="$DB_PASSWORD" \
        HIPS_DB_HOST="127.0.0.1" PYTHONPATH="$PWD" \
        python3 hips.py --guardar-db --json
}

# ======================================================================
paso "PARTE 1 - HARDENING DEL SISTEMA OPERATIVO (10 controles minimo)"
# ======================================================================

sub "Control 1: SELinux en modo enforcing"
getenforce
pausa

sub "Control 2: firewalld con zona restrictiva"
sudo firewall-cmd --list-all || true
sudo systemctl status firewalld
pausa

sub "Control 3: SSH con acceso restringido"
sudo sshd -T | grep -E 'permitrootlogin|passwordauthentication|pubkeyauthentication'
pausa

sub "Control 4: /tmp montado con noexec, nosuid, nodev"
cat /etc/fstab
pausa

sub "Control 5: auditd activo con reglas personalizadas"
sudo systemctl status auditd
sudo auditctl -l
pausa

sub "Control 6: principio de minimo privilegio (servicio hips oneshot)"
sudo systemctl status hips
pausa

sub "Control 7: servicios innecesarios deshabilitados"
systemctl status avahi-daemon cups bluetooth nfs-server rpcbind
pausa

sub "Control 8: banner de login y aviso legal"
sudo sshd -T | grep banner
cat /etc/issue.net
pausa

sub "Control 9: actualizaciones automaticas de seguridad"
rpm -q dnf-automatic
systemctl status dnf-automatic.timer
grep -E 'apply_updates|upgrade_type' /etc/dnf/automatic.conf
pausa

sub "Control 10: permisos restrictivos en archivos criticos"
ls -l /etc/passwd /etc/shadow /etc/sudoers
ls -ld /var/log/hips
sudo sudo sudo sudo ls -l /var/log/hips
pausa

sub "PostgreSQL instalado y configurado"
rpm -q postgresql-server
pausa

# ======================================================================
paso "PARTE 2 - HARDENING CIS DE LA BASE DE DATOS (7+ practicas)"
# ======================================================================

sub "CIS 1: usuario de aplicacion sin superusuario"
PGPASSWORD="$DB_PASSWORD" psql -h 127.0.0.1 -U hips_app -d hips_db -c \
    "SELECT current_user, current_database(); SELECT usename, usesuper FROM pg_user WHERE usename='hips_app';"
pausa

sub "CIS 2: SSL activo"
sudo -u postgres psql -d hips_db -c "SHOW ssl;"
pausa

sub "CIS 3: registro de conexiones y desconexiones"
sudo -u postgres psql -d hips_db -c "SELECT name, setting FROM pg_settings WHERE name IN ('log_connections','log_disconnections') ORDER BY name;"
pausa

sub "CIS 4: listen_addresses restringido a localhost"
sudo -u postgres psql -d hips_db -c "SHOW listen_addresses;"
pausa

sub "CIS 5: password_encryption = scram-sha-256"
sudo -u postgres psql -d hips_db -c "SHOW password_encryption;"
pausa

sub "CIS 6: registro de errores de autenticacion"
sudo -u postgres psql -d hips_db -c "SHOW log_min_error_statement;"
pausa

sub "CIS 7: pg_hba.conf solo local con scram"
sudo grep -Ev '^\s*#|^\s*$' /var/lib/pgsql/data/pg_hba.conf
pausa

sub "Permisos de acceso a la base de datos"
sudo -u postgres psql -c "\l+"
sudo -u postgres psql -c "\l+ hips_db"
sudo -u postgres psql -d hips_db -c "\du hips_app"
sudo -u postgres psql -c "
SELECT rolname,
       rolsuper,
       rolcreatedb,
       rolcreaterole,
       rolreplication
FROM pg_roles
WHERE rolname='hips_app';"
pausa

sub "Ninguna contrasena expuesta en el codigo fuente"
grep -RniE 'password|passwd|pwd|secret|token|api[_-]?key|PGPASSWORD' . \
  --exclude-dir=.git \
  --exclude='*.png' \
  --exclude='*.jpg'
pausa

sub "Configuracion de modulos guardada en BD (no en archivos planos)"
sudo -u postgres psql -d hips_db -c "SELECT modulo, habilitado, intervalo_segundos, umbral, configuracion FROM configuracion_modulos ORDER BY modulo;"
pausa

sub "Baseline de binarios generado y guardado de forma segura"
sudo -u postgres psql -d hips_db -c "\dt"
sudo -u postgres psql -d hips_db -c "\d baseline_archivos"
sudo -u postgres psql -d hips_db -c "SELECT COUNT(*) AS total_baseline_db FROM baseline_archivos WHERE ruta IS NOT NULL;" && sudo -u postgres psql -d hips_db -c "SELECT ruta, sha256, actualizado_en FROM baseline_archivos WHERE ruta IS NOT NULL ORDER BY ruta LIMIT 10;"
pausa

# ======================================================================
paso "MODULO i - INTEGRIDAD DE ARCHIVOS"
# ======================================================================

sub "Deteccion de modificacion de binarios vs baseline (hash falso)"
cd "$PROY" && sudo env PYTHONPATH="$PWD" python3 -c 'from copy import deepcopy; from detection.file_integrity import cargar_baseline, verificar_integridad; b=deepcopy(cargar_baseline("db://baseline_archivos")); f="/bin/bash" if "/bin/bash" in b else next(iter(b)); b[f]["sha256"]="HASH_FALSO"; a=verificar_integridad(b, registrar_alertas=False); print("archivo_probado =", f); print("alertas_detectadas =", len(a)); print("tipo =", a[0]["tipo"] if a else "SIN_ALERTAS"); print("detalle =", a[0]["detalle"] if a else "SIN_DETALLE")'
pausa

sub "Deteccion de modificaciones en /etc/passwd"
cd "$PROY" && sudo env PYTHONPATH="$PWD" python3 -c 'from copy import deepcopy; from detection.file_integrity import cargar_baseline, verificar_integridad; b=deepcopy(cargar_baseline("db://baseline_archivos")); b["/etc/passwd"]["sha256"]="HASH_FALSO"; a=verificar_integridad(b, registrar_alertas=False); print("archivo_probado = /etc/passwd"); print("alertas_detectadas =", len(a)); print("tipo =", a[0]["tipo"] if a else "SIN_ALERTAS"); print("detalle =", a[0]["detalle"] if a else "SIN_DETALLE")'
pausa

sub "Deteccion de modificaciones en /etc/shadow"
cd "$PROY" && sudo env PYTHONPATH="$PWD" python3 -c 'from copy import deepcopy; from detection.file_integrity import cargar_baseline, verificar_integridad; b=deepcopy(cargar_baseline("db://baseline_archivos")); b["/etc/shadow"]["sha256"]="HASH_FALSO"; a=verificar_integridad(b, registrar_alertas=False); print("archivo_probado = /etc/shadow"); print("alertas_detectadas =", len(a)); print("tipo =", a[0]["tipo"] if a else "SIN_ALERTAS"); print("detalle =", a[0]["detalle"] if a else "SIN_DETALLE")'
pausa

sub "Accion de prevencion implementada (ultimas 5 alarmas + accion)"
sudo -u postgres psql -d hips_db -c "SELECT a.id, a.tipo_alarma, a.modulo, a.descripcion, a.resuelta, ap.accion, ap.resultado FROM alarmas a JOIN acciones_prevencion ap ON ap.alarma_id = a.id ORDER BY a.id DESC LIMIT 5;"
pausa

sub "Prueba/Demo funcionando (ciclo real completo + logs)"
cd "$PROY" && sudo env HIPS_DB_NAME="hips_db" HIPS_DB_USER="hips_app" HIPS_DB_PASSWORD="$DB_PASSWORD" HIPS_DB_HOST="127.0.0.1" HIPS_ADMIN_EMAIL="ile" HIPS_SENDMAIL_PATH="/usr/sbin/sendmail" PYTHONPATH="$PWD" python3 hips.py --guardar-db --prevenir --json && sudo -u postgres psql -d hips_db -c "SELECT id, timestamp, tipo_alarma, modulo, severidad, descripcion, resuelta FROM alarmas ORDER BY id DESC LIMIT 5;" && sudo tail -n 20 /var/log/hips/alarmas.log && sudo tail -n 20 /var/log/hips/prevencion.log
pausa

# ======================================================================
paso "MODULO ii - USUARIOS CONECTADOS"
# ======================================================================

sub "Verificacion de usuarios conectados y origen"
echo "=== usuarios conectados y origen ==="
who -uH
w -i
last -ai | head -n 10

cd "$PROY"
sudo env HIPS_DB_NAME="hips_db" HIPS_DB_USER="hips_app" HIPS_DB_PASSWORD="$DB_PASSWORD" HIPS_DB_HOST="127.0.0.1" PYTHONPATH="$PWD" python3 hips.py --guardar-db --json

sudo -u postgres psql -d hips_db -c "SELECT id, timestamp, tipo_alarma, modulo, ip_origen, descripcion, resuelta FROM alarmas WHERE modulo='user_monitor' ORDER BY id DESC LIMIT 5;"

sudo -u postgres psql -d hips_db -c "SELECT id, timestamp, modulo, evento, detalle FROM eventos_sistema ORDER BY id DESC LIMIT 10;"
pausa

sub "Accion de prevencion implementada (usuarios)"
sudo -u postgres psql -d hips_db -c "SELECT a.id, a.tipo_alarma, a.modulo, a.ip_origen, a.descripcion, a.resuelta, COALESCE(ap.accion,'SIN_ACCION') AS accion, COALESCE(ap.resultado,'SIN_RESULTADO') AS resultado FROM alarmas a LEFT JOIN acciones_prevencion ap ON ap.alarma_id = a.id WHERE a.modulo='user_monitor' ORDER BY a.id DESC LIMIT 5;"

sudo grep -iE 'user_monitor|usuario|origen|horario|conexion|bloquear|password' /var/log/hips/prevencion.log | tail -n 20
pausa

sub "Prueba/demo funcionando (usuarios) - ciclo completo real"
cd "$PROY" && \
sudo env \
  HIPS_DB_NAME="hips_db" \
  HIPS_DB_USER="hips_app" \
  HIPS_DB_PASSWORD="$DB_PASSWORD" \
  HIPS_DB_HOST="127.0.0.1" \
  PYTHONPATH="$PWD" \
  python3 hips.py --guardar-db --prevenir --json && \
sudo -u postgres psql -d hips_db -c "SELECT id, timestamp, tipo_alarma, modulo, severidad, ip_origen, descripcion, resuelta FROM alarmas WHERE modulo='user_monitor' ORDER BY id DESC LIMIT 5;" && \
sudo -u postgres psql -d hips_db -c "SELECT a.id, a.tipo_alarma, a.modulo, a.descripcion, a.resuelta, COALESCE(ap.accion,'SIN_ACCION') AS accion, COALESCE(ap.resultado,'SIN_RESULTADO') AS resultado FROM alarmas a LEFT JOIN acciones_prevencion ap ON ap.alarma_id = a.id WHERE a.modulo='user_monitor' ORDER BY a.id DESC LIMIT 5;" && \
sudo tail -n 20 /var/log/hips/alarmas.log && \
sudo tail -n 20 /var/log/hips/prevencion.log
pausa

# ======================================================================
paso "MODULO iii - SNIFFERS Y MODO PROMISCUO"
# ======================================================================

sub "Iniciar tcpdump, wireshark y ethereal para la demo"
echo "=== iniciar tcpdump, wireshark y ethereal para demo ==="

sudo tcpdump -i lo -w /tmp/hips_tcpdump_demo.pcap >/tmp/hips_tcpdump_demo.log 2>&1 &
TCPDUMP_PID=$!

bash -c 'exec -a wireshark sleep 600' &
WIRESHARK_PID=$!

bash -c 'exec -a ethereal sleep 600' &
ETHEREAL_PID=$!

echo "tcpdump_pid=$TCPDUMP_PID"
echo "wireshark_pid=$WIRESHARK_PID"
echo "ethereal_pid=$ETHEREAL_PID"

echo "=== procesos activos ==="
ps -eo pid,comm,args | grep -E '[t]cpdump|[w]ireshark|[e]thereal'

ciclo_hips
pausa

sub "Verificar que ya no quedan sniffers activos (deberia haberlos matado la prevencion)"
ps -eo pid,comm,args | grep -E '[t]cpdump|[w]ireshark|[t]shark|[e]thereal' || echo "OK: no quedan sniffers activos"
pausa

sub "Deteccion de tcpdump / wireshark / ethereal en ejecucion"
sudo -u postgres psql -d hips_db -c "SELECT a.id, a.tipo_alarma, a.modulo, a.descripcion, a.resuelta, ap.accion, ap.resultado FROM alarmas a JOIN acciones_prevencion ap ON ap.alarma_id = a.id WHERE a.modulo='sniffers' ORDER BY a.id DESC LIMIT 10;"
pausa

sub "Prevencion: bloqueo o eliminacion de la herramienta (misma tabla, foco en accion/resultado)"
sudo -u postgres psql -d hips_db -c "SELECT a.id, a.tipo_alarma, a.modulo, a.descripcion, a.resuelta, ap.accion, ap.resultado FROM alarmas a JOIN acciones_prevencion ap ON ap.alarma_id = a.id WHERE a.modulo='sniffers' ORDER BY a.id DESC LIMIT 10;"
pausa

# ======================================================================
paso "MODULO iv - ANALISIS DE LOGS (Failed Password / access.log)"
# ======================================================================

sub "Errores repetidos desde una IP en access.log (scanner HTTP)"
cd "$PROY" && sudo mkdir -p /var/log/httpd && sudo bash -c 'for i in $(seq 1 25); do echo "198.51.100.25 - - [11/Jul/2026:18:20:$i -0300] \"GET /ruta_inexistente_$i HTTP/1.1\" 404 123"; done >> /var/log/httpd/access.log' && sudo env HIPS_DB_NAME="hips_db" HIPS_DB_USER="hips_app" HIPS_DB_PASSWORD="$DB_PASSWORD" HIPS_DB_HOST="127.0.0.1" PYTHONPATH="$PWD" python3 hips.py --guardar-db --prevenir --json && sudo -u postgres psql -d hips_db -c "SELECT id, timestamp, tipo_alarma, modulo, severidad, ip_origen, descripcion, resuelta FROM alarmas WHERE modulo='system_logs' AND tipo_alarma='scanner_http' ORDER BY id DESC LIMIT 10;"
pausa

# ======================================================================
paso "MODULO v - COLA DE CORREO (envio masivo)"
# ======================================================================

sub "Envio masivo de mails - prueba completa con backup y TAG de limpieza"
bash -lc 'cd '"$PROY"'; echo "=== PRUEBA ENVIO MASIVO DE MAILS ==="; sudo systemctl stop hips.timer || true; sudo systemctl reset-failed postfix || true; sudo systemctl start postfix || true; BACKUP="/tmp/maillog_backup_hips_$(date +%H%M%S)"; sudo cp -a /var/log/maillog "$BACKUP" 2>/dev/null || true; sudo bash -c ": > /var/log/maillog"; TAG="HIPS_ENVIO_MASIVO_$(date +%H%M%S)"; REMITENTE="spamtest_${TAG}@local"; for i in 1 2 3 4 5 6; do sudo bash -c "echo \"Jul 11 18:30:0$i localhost postfix/smtp[222$i]: ABC00$i: from=<$REMITENTE>, to=<destino$i@example.com>, status=sent $TAG\" >> /var/log/maillog"; done; sudo env HIPS_DB_NAME="hips_db" HIPS_DB_USER="hips_app" HIPS_DB_PASSWORD="'"$DB_PASSWORD"'" HIPS_DB_HOST="127.0.0.1" PYTHONPATH="$PWD" python3 hips.py --guardar-db --prevenir --json; echo "=== ALARMA ==="; sudo -u postgres psql -d hips_db -c "SELECT id, timestamp, tipo_alarma, modulo, severidad, descripcion, resuelta FROM alarmas WHERE tipo_alarma='"'"'envio_masivo_correo'"'"' ORDER BY id DESC LIMIT 3;"; echo "=== ACCION PREVENTIVA ==="; sudo -u postgres psql -d hips_db -c "SELECT a.id, a.tipo_alarma, a.modulo, ap.accion, ap.resultado FROM alarmas a LEFT JOIN acciones_prevencion ap ON ap.alarma_id=a.id WHERE a.tipo_alarma='"'"'envio_masivo_correo'"'"' ORDER BY a.id DESC LIMIT 3;"; sudo sed -i "/$TAG/d" /var/log/maillog; sudo systemctl start hips.timer; echo "postfix=$(systemctl is-active postfix)"; echo "hips_timer=$(systemctl is-active hips.timer)"; echo "backup_maillog=$BACKUP"; echo "=== FIN ==="'
pausa

sub "Accion: bloqueo de IP"
sudo -u postgres psql -d hips_db -c "SELECT a.id, a.tipo_alarma, a.modulo, a.ip_origen, a.descripcion, a.resuelta, ap.accion, ap.resultado FROM alarmas a JOIN acciones_prevencion ap ON ap.alarma_id = a.id WHERE ap.accion ILIKE '%bloquear%' OR ap.accion ILIKE '%firewall%' ORDER BY a.id DESC LIMIT 10;" && echo "=== FIREWALL RICH RULES ===" && sudo firewall-cmd --list-rich-rules && echo "=== FIREWALL GENERAL ===" && sudo firewall-cmd --list-all
pausa

sub "Accion: cambio de contrasena de usuario"
sudo -u postgres psql -d hips_db -c "SELECT a.id, a.tipo_alarma, a.modulo, a.descripcion, a.resuelta, ap.accion, ap.resultado FROM alarmas a JOIN acciones_prevencion ap ON ap.alarma_id=a.id WHERE a.tipo_alarma='password_comprometida' ORDER BY a.id DESC LIMIT 10;"
pausa

sub "Accion: bloqueo de usuario"
sudo -u postgres psql -d hips_db -c "SELECT a.id, a.tipo_alarma, a.modulo, a.descripcion, a.resuelta, ap.accion, ap.resultado FROM alarmas a JOIN acciones_prevencion ap ON ap.alarma_id = a.id WHERE ap.accion ILIKE '%bloquear_usuario%' OR ap.accion ILIKE '%lock%' OR ap.accion ILIKE '%usuario%' ORDER BY a.id DESC LIMIT 10;"
pausa

sub "Accion: reinicio del servicio de correo"
sudo -u postgres psql -d hips_db -c "SELECT a.id, a.tipo_alarma, a.modulo, a.descripcion, a.resuelta, ap.accion, ap.resultado FROM alarmas a JOIN acciones_prevencion ap ON ap.alarma_id = a.id WHERE ap.accion ILIKE '%correo%' OR ap.accion ILIKE '%postfix%' OR ap.accion ILIKE '%mail%' ORDER BY a.id DESC LIMIT 10;" && sudo systemctl status postfix --no-pager
pausa

sub "Verificacion del tamano de la cola de mails"
echo "=== TAMAÑO DE COLA DE CORREO ===" && mailq | head -n 20 && echo "=== RESUMEN COLA ===" && postqueue -p | tail -n 1
pausa

sub "Umbral definido para envio masivo"
sudo -u postgres psql -d hips_db -c "SELECT modulo, habilitado, intervalo_segundos, umbral, configuracion FROM configuracion_modulos WHERE modulo='mail_queue';"
pausa

sub "Prevencion: bloqueo de IP o usuario generador"
cd /tmp && sudo -u postgres psql -d hips_db -c "SELECT a.id, a.tipo_alarma, a.modulo, a.descripcion, a.resuelta, ap.accion, ap.resultado FROM alarmas a JOIN acciones_prevencion ap ON ap.alarma_id=a.id WHERE a.modulo='mail_queue' AND a.tipo_alarma='envio_masivo_correo' AND ap.accion='bloquear_usuario' ORDER BY a.id DESC LIMIT 5;"
pausa

# ======================================================================
paso "MODULO vi - PROCESOS CON ALTO CONSUMO DE RECURSOS"
# ======================================================================

sub "Monitoreo de % de memoria por proceso"
cd "$PROY" && python3 -c 'from detection.process_monitor import detectar_procesos_sospechosos; txt="PID USER %CPU %MEM COMMAND ARGS\n1234 test 0.0 85.5 python python memtest"; a=detectar_procesos_sospechosos(txt, memoria_umbral=80.0); print(a)'
pausa

sub "Criterio de tiempo de consumo excesivo (config del modulo)"
sudo -u postgres psql -d hips_db -c "SELECT modulo, habilitado, intervalo_segundos, umbral, configuracion
FROM configuracion_modulos
WHERE modulo='process_monitor';"
pausa

sub "Logica normal vs. anomalo"
cd "$PROY" && python3 - <<'PY'
from detection.process_monitor import detectar_procesos_sospechosos

normal = "PID USER %CPU %MEM COMMAND ARGS\n1111 test 1.0 2.0 python python normal"
anomalo = "PID USER %CPU %MEM COMMAND ARGS\n2222 test 1.0 85.5 python python consumo_alto"

print("=== PROCESO NORMAL ===")
print(detectar_procesos_sospechosos(normal, memoria_umbral=80.0))

print("=== PROCESO ANOMALO ===")
print(detectar_procesos_sospechosos(anomalo, memoria_umbral=80.0))
PY
pausa

sub "Prevencion: terminar proceso"
cd /tmp && sudo -u postgres psql -d hips_db -c "SELECT a.id, a.tipo_alarma, a.modulo, a.descripcion, a.resuelta, ap.accion, ap.resultado FROM alarmas a JOIN acciones_prevencion ap ON ap.alarma_id = a.id WHERE a.modulo='process_monitor' ORDER BY a.id DESC LIMIT 10;"
pausa

# ======================================================================
paso "MODULO vii - DIRECTORIO /tmp"
# ======================================================================

sub "Creando script ejecutable oculto en /tmp para generar el evento real"
echo '#!/bin/bash' > /tmp/.update.sh
echo 'echo hola desde un script sospechoso' >> /tmp/.update.sh
chmod +x /tmp/.update.sh
ls -la /tmp/.update.sh
cd "$PROY"
ciclo_hips
pausa

sub "Deteccion de nombres extranos o scripts ejecutables en /tmp"
cd /tmp && sudo -u postgres psql -d hips_db -c "SELECT a.id, a.tipo_alarma, a.modulo, a.descripcion, a.resuelta, ap.accion, ap.resultado FROM alarmas a JOIN acciones_prevencion ap ON ap.alarma_id=a.id WHERE a.modulo='tmp_monitor' AND ap.resultado='ejecutado' ORDER BY a.id DESC LIMIT 10;"
pausa

sub "Prevencion: eliminacion o cuarentena"
cd /tmp && sudo -u postgres psql -d hips_db -c "SELECT a.id, a.tipo_alarma, a.modulo, a.descripcion, a.resuelta, ap.accion, ap.resultado FROM alarmas a JOIN acciones_prevencion ap ON ap.alarma_id=a.id WHERE a.modulo='tmp_monitor' AND ap.accion IN ('cuarentenar_archivo','archivo_ya_prevenido') ORDER BY a.id DESC LIMIT 10;" && echo "=== buscar cuarentena ===" && sudo find /var /tmp -iname '*quarantine*' -o -iname '*cuarentena*' 2>/dev/null | head -n 20
pausa

# ======================================================================
paso "MODULO viii - ATAQUES DDoS"
# ======================================================================

sub "Deteccion calibrada con muestra de log DNS"
cd /tmp && sudo -u postgres psql -d hips_db -c "SELECT a.id, a.tipo_alarma, a.modulo, a.ip_origen, a.resuelta, ap.accion, ap.resultado FROM alarmas a JOIN acciones_prevencion ap ON ap.alarma_id=a.id WHERE a.modulo='ddos_monitor' AND a.tipo_alarma='dns_query_flood' ORDER BY a.id DESC LIMIT 5;"
pausa

sub "Prevencion: bloqueo de IP o baja del servicio"
sudo -u postgres psql -d hips_db -c "SELECT a.id, a.tipo_alarma, a.modulo, a.ip_origen, a.descripcion, a.resuelta,
       ap.accion, ap.resultado
FROM alarmas a
JOIN acciones_prevencion ap ON ap.alarma_id = a.id
WHERE a.modulo='ddos_monitor'
ORDER BY a.id DESC
LIMIT 10;"

echo "=== FIREWALL ==="
sudo firewall-cmd --list-rich-rules
sudo firewall-cmd --list-all
pausa

# ======================================================================
paso "MODULO ix - ARCHIVOS CRON SOSPECHOSOS"
# ======================================================================

sub "Revision de tareas cron del sistema (cron falso de prueba)"
cd "$PROY" && sudo systemctl stop hips.timer || true && echo "=== crear cron falso de prueba ===" && echo '* * * * * root /tmp/.update.sh' | sudo tee /etc/cron.d/hips_prueba_cron_monitor >/dev/null && sudo chmod 644 /etc/cron.d/hips_prueba_cron_monitor && sudo env HIPS_DB_NAME="hips_db" HIPS_DB_USER="hips_app" HIPS_DB_PASSWORD="$DB_PASSWORD" HIPS_DB_HOST="127.0.0.1" PYTHONPATH="$PWD" python3 hips.py --guardar-db --prevenir --json && cd /tmp && sudo -u postgres psql -d hips_db -c "SELECT id, timestamp, tipo_alarma, modulo, severidad, descripcion, resuelta FROM alarmas WHERE modulo='cron_monitor' ORDER BY id DESC LIMIT 10;" && echo "=== limpiar prueba ===" && sudo rm -f /etc/cron.d/hips_prueba_cron_monitor && cd "$PROY" && sudo systemctl start hips.timer && systemctl is-active hips.timer
pausa

sub "Identificacion de tareas con rutas/nombres sospechosos"
cd /tmp && sudo -u postgres psql -d hips_db -c "SELECT a.id, a.tipo_alarma, a.modulo, a.descripcion, a.resuelta, ap.accion, ap.resultado FROM alarmas a LEFT JOIN acciones_prevencion ap ON ap.alarma_id=a.id WHERE a.modulo='cron_monitor' ORDER BY a.id DESC LIMIT 10;"
pausa

# ======================================================================
paso "MODULO x - INTENTOS DE ACCESO INVALIDOS"
# ======================================================================

sub "Deteccion de intentos repetidos de un mismo usuario (generar logs de prueba)"
sudo bash -c 'cat >> /var/log/secure <<EOF
Jul 12 15:10:01 localhost sshd[5001]: Failed password for invalid user admin from 203.0.113.80 port 5001 ssh2
Jul 12 15:10:02 localhost sshd[5002]: Failed password for invalid user admin from 203.0.113.80 port 5002 ssh2
Jul 12 15:10:03 localhost sshd[5003]: Failed password for invalid user admin from 203.0.113.80 port 5003 ssh2
Jul 12 15:10:04 localhost sshd[5004]: Failed password for invalid user admin from 203.0.113.80 port 5004 ssh2
Jul 12 15:10:05 localhost sshd[5005]: Failed password for invalid user admin from 203.0.113.80 port 5005 ssh2
EOF'

cd "$PROY"
ciclo_hips

sub "Verificar alarma (mismo usuario repetido)"
sudo -u postgres psql -d hips_db -c "SELECT id, timestamp, tipo_alarma, modulo, severidad, ip_origen, descripcion, resuelta
FROM alarmas
WHERE modulo IN ('auth_failures','system_logs')
ORDER BY id DESC
LIMIT 10;"
pausa

sub "Deteccion de credential stuffing (varios usuarios, misma IP)"
cd "$PROY" && sudo systemctl stop hips.timer || true && TAG="HIPS_CRED_STUFF_$(date +%H%M%S)" && for u in admin oracle postgres backup test; do sudo bash -c "echo \"Jul 12 15:20:01 localhost sshd[6001]: Failed password for invalid user $u from 203.0.113.90 port 6001 ssh2 $TAG\" >> /var/log/secure"; done && sudo bash -c ': > /var/log/maillog' && sudo env HIPS_DB_NAME="hips_db" HIPS_DB_USER="hips_app" HIPS_DB_PASSWORD="$DB_PASSWORD" HIPS_DB_HOST="127.0.0.1" PYTHONPATH="$PWD" python3 hips.py --guardar-db --prevenir --json && cd /tmp && sudo -u postgres psql -d hips_db -c "SELECT a.id, a.tipo_alarma, a.modulo, a.severidad, a.ip_origen, a.descripcion, a.resuelta, ap.accion, ap.resultado FROM alarmas a LEFT JOIN acciones_prevencion ap ON ap.alarma_id=a.id WHERE a.modulo='auth_failures' AND (a.tipo_alarma='credential_stuffing' OR a.ip_origen='203.0.113.90' OR a.descripcion ILIKE '%203.0.113.90%') ORDER BY a.id DESC LIMIT 10;" && cd "$PROY" && sudo systemctl start hips.timer && systemctl is-active hips.timer

sudo firewall-cmd --permanent --remove-rich-rule='rule family="ipv4" source address="203.0.113.90" reject' || true && sudo firewall-cmd --reload
pausa

# ======================================================================
paso "NOTIFICACIONES POR CORREO Y DASHBOARD"
# ======================================================================

sub "Email al admin por cada alarma detectada"
echo "=== ULTIMAS ALARMAS EN POSTGRESQL ===" && cd /tmp && sudo -u postgres psql -d hips_db -c "SELECT id, timestamp, tipo_alarma, modulo, severidad, descripcion FROM alarmas ORDER BY id DESC LIMIT 5;" && echo "=== EMAIL LOCAL RECIBIDO POR ADMIN ile ===" && sudo grep -iE 'Subject: \[HIPS\]|Alerta del sistema HIPS|ddos_monitor|auth_failures|dns_query_flood|credential_stuffing|multiples_intentos' /var/spool/mail/ile | tail -n 40 && echo "=== ESTADO POSTFIX ===" && systemctl is-active postfix
pausa

sub "Email al admin por cada accion de prevencion"
echo "=== EMAIL POR ACCION DE PREVENCION ===" && sudo grep -iE 'HIPS PREVENCION|Accion preventiva ejecutada|Accion preventiva:|Resultado: ejecutado|IP:|bloquear_ip|cuarentenar_archivo' /var/spool/mail/ile | tail -n 40 && echo "=== LOG EMAIL PREVENCION ===" && sudo tail -n 10 /var/log/hips/prevencion_email.log
pausa

sub "Dashboard visible con las alarmas"
echo "=== SERVICIO WEB HIPS ===" && systemctl is-active hips-web.service && curl -s -o /dev/null -w "HTTP_CODE=%{http_code}\n" http://127.0.0.1:5000/login && echo "=== ULTIMAS ALARMAS ===" && cd /tmp && sudo -u postgres psql -d hips_db -c "SELECT id, timestamp, tipo_alarma, modulo, severidad, descripcion, resuelta FROM alarmas ORDER BY id DESC LIMIT 10;"
echo "   [NOTA] El login con usuario/contrasena en la interfaz web se verifica a mano en el navegador con las credenciales de /etc/hips/hips.env"
pausa

sub "Directorio /var/log/hips/ creado"
echo "=== DIRECTORIO /var/log/hips ===" && sudo ls -ld /var/log/hips && echo "=== ARCHIVOS DE LOG HIPS ===" && sudo sudo sudo sudo sudo ls -l /var/log/hips
pausa

# ======================================================================
paso "PRUEBA INTEGRAL FINAL - alarmas.log CON TODAS LAS ALARMAS JUNTAS"
# ======================================================================

sub "Generando DNS flood + failed password juntos, y revisando alarmas.log completo"
cd "$PROY" && sudo systemctl stop hips.timer || true && sudo bash -c ': > /var/log/maillog' && sudo mkdir -p /var/log/named && sudo bash -c ': > /var/log/named/query.log' && for i in $(seq 1 80); do echo "12-Jul-2026 18:50:00.$i client 203.0.113.60#53$i (example.com): query: example.com IN A +E" | sudo tee -a /var/log/named/query.log >/dev/null; done && for i in $(seq 1 6); do sudo bash -c "echo \"Jul 12 18:50:0$i localhost sshd[700$i]: Failed password for invalid user admin from 203.0.113.61 port 700$i ssh2\" >> /var/log/secure"; done && sudo env HIPS_DB_NAME="hips_db" HIPS_DB_USER="hips_app" HIPS_DB_PASSWORD="$DB_PASSWORD" HIPS_DB_HOST="127.0.0.1" HIPS_ADMIN_EMAIL="ile" PYTHONPATH="$PWD" python3 hips.py --guardar-db --prevenir --json && echo "=== alarmas.log ===" && sudo grep -iE 'dns_query_flood|multiples_intentos|credential|ddos|auth|mail|correo|tmp|cron|sniffer|scanner' /var/log/hips/alarmas.log | tail -n 40 && sudo systemctl start hips.timer
pausa

sub "prevencion.log con todas las acciones"
echo "=== prevencion.log con acciones preventivas ===" && sudo grep -iE 'bloquear_ip|bloquear_usuario|finalizar_proceso|cuarentenar_archivo|reiniciar_postfix|cambiar_password_usuario|limpiar_cola_correo|Accion de prevencion' /var/log/hips/prevencion.log | tail -n 30
pausa

sub "Formato exacto: dd/mes/yyyy :: Tipo :: IP origen"
echo "=== FORMATO alarmas.log ===" && sudo tail -n 10 /var/log/hips/alarmas.log && echo "=== VALIDAR FORMATO dd/mm/yyyy :: Tipo :: IP ===" && sudo grep -E '^[0-9]{2}/[0-9]{2}/[0-9]{4} :: [A-Z0-9_]+ :: .+' /var/log/hips/alarmas.log | tail -n 10
pausa

paso "DEMO MAESTRA TERMINADA - revisa la salida de arriba modulo por modulo"
echo "Corre scripts/limpiar_demo_maestra.sh para eliminar los rastros de prueba que quedaron."
