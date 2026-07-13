# HIPS – Host-based Intrusion Prevention System

Sistema académico de **detección y prevención de intrusiones basado en host (HIPS)** desarrollado sobre **Rocky Linux**.  
El proyecto monitorea eventos del sistema, detecta comportamientos anómalos, registra alarmas, ejecuta acciones preventivas y notifica al administrador.

**Universidad Católica Nuestra Señora de la Asunción**
**Materia:** Sistemas Operativos 2
**Autores:** Ileana Sanabria y Elias Pont

---

## Índice

1. [Objetivo](#1-objetivo)
2. [Tecnologías utilizadas](#2-tecnologías-utilizadas)
3. [Justificación del lenguaje elegido](#3-justificación-del-lenguaje-elegido)
4. [Estructura general del proyecto](#4-estructura-general-del-proyecto)
5. [Variables de entorno](#5-variables-de-entorno)
6. [Base de datos](#6-base-de-datos)
7. [Módulos implementados](#7-módulos-implementados)
8. [Acciones preventivas implementadas](#8-acciones-preventivas-implementadas)
9. [Bitácoras](#9-bitácoras)
10. [Notificaciones por email](#10-notificaciones-por-email)
11. [Interfaz web](#11-interfaz-web)
12. [Servicios systemd](#12-servicios-systemd)
13. [Hardening aplicado](#13-hardening-aplicado)
14. [Pruebas realizadas](#14-pruebas-realizadas)
15. [Consultas útiles](#15-consultas-útiles)
16. [Historial de desarrollo](#16-historial-de-desarrollo)
17. [Contribuciones por integrante](#17-contribuciones-por-integrante)
18. [Seguridad y buenas prácticas](#18-seguridad-y-buenas-prácticas)
19. [Estado del proyecto](#19-estado-del-proyecto)
20. [Autores](#20-autores)

---

## 1. Objetivo

El objetivo del proyecto es implementar un HIPS capaz de:

- Detectar modificaciones en archivos críticos del sistema.
- Monitorear usuarios conectados y accesos sospechosos.
- Detectar sniffers e interfaces en modo promiscuo.
- Analizar logs del sistema.
- Controlar la cola de correo.
- Detectar procesos con alto consumo de memoria.
- Detectar archivos sospechosos en `/tmp`.
- Detectar patrones de DDoS en logs DNS.
- Revisar tareas cron sospechosas.
- Detectar intentos de acceso no válidos y credential stuffing.
- Ejecutar acciones preventivas automáticas.
- Registrar alarmas y acciones en PostgreSQL y en `/var/log/hips/`.
- Mostrar alertas y configuración desde una interfaz web.

---

## 2. Tecnologías utilizadas

- **Sistema operativo:** Rocky Linux 9.8
- **Lenguaje principal:** Python 3
- **Base de datos:** PostgreSQL
- **Interfaz web:** Flask (`>=3.1,<4`)
- **Driver PostgreSQL:** psycopg2-binary (`>=2.9,<3`)
- **Correo local:** Postfix / Sendmail
- **Firewall:** firewalld
- **Automatización:** systemd service + systemd timer
- **Control de versiones:** Git / GitHub

Dependencias declaradas en `requirements.txt`:

```text
Flask>=3.1,<4
psycopg2-binary>=2.9,<3
```

---

## 3. Justificación del lenguaje elegido

Se eligió **Python** porque permite automatizar tareas del sistema, leer logs, calcular hashes, inspeccionar procesos, interactuar con PostgreSQL, ejecutar acciones preventivas y desarrollar una interfaz web liviana.

Además, su estructura facilita dividir el proyecto en módulos independientes de detección, prevención, base de datos, notificación y dashboard.

---

## 4. Estructura general del proyecto

```text
hips-so2/
├── hips.py
├── requirements.txt
├── core/
│   ├── runner.py
│   ├── engine.py
│   ├── alert_service.py
│   ├── email_notifier.py
│   └── hips_logger.py
├── detection/
│   ├── auth_failures.py
│   ├── cron_monitor.py
│   ├── ddos_monitor.py
│   ├── file_integrity.py
│   ├── mail_queue.py
│   ├── process_monitor.py
│   ├── sniffers.py
│   ├── system_logs.py
│   ├── tmp_monitor.py
│   └── user_monitor.py
├── prevention/
│   ├── actions.py
│   └── engine.py
├── db/
│   ├── connection.py
│   ├── repository.py
│   └── migrations/
├── web/
│   ├── app.py
│   ├── static/
│   │   └── style.css
│   └── templates/
│       ├── login.html
│       └── dashboard.html
├── config/
│   ├── baseline_archivos.json
│   ├── hips.env.example
│   └── systemd/
│       ├── hips.service
│       └── hips.timer
├── deploy/
│   └── systemd/
│       ├── hips.service
│       └── hips-web.service
├── scripts/
│   ├── run_hips_once.sh
│   ├── demo_maestra.sh
│   └── limpiar_demo_maestra.sh
├── alerts/
├── docs/
├── tests/
├── EVIDENCIAS, CAPTURAS Y CHECKLIST- HIPS PONT-SANABRIA.pdf
└── README.md
```

> A partir de esta versión, el runner central (`core/runner.py`) delega la persistencia y el ruteo de alarmas en `core/alert_service.py`, y el envío de notificaciones se separó en `core/email_notifier.py`. Cada módulo de detección vive ahora en su propio archivo dentro de `detection/` (incluyendo `file_integrity.py`, `mail_queue.py` y `sniffers.py`, que antes solo estaban documentados de forma conceptual). El baseline de integridad se persiste en PostgreSQL (`db://baseline_archivos`) y el módulo de DDoS ya sabe leer logs de consultas DNS estilo BIND, además de conexiones de red.

---

## 5. Variables de entorno

El sistema evita exponer contraseñas en el código fuente. Las credenciales y parámetros sensibles se cargan mediante variables de entorno.

Archivo recomendado:

```text
/etc/hips/hips.env
```

Ejemplo:

```bash
HIPS_DB_NAME="hips_db"
HIPS_DB_USER="hips_app"
HIPS_DB_PASSWORD="CAMBIAR_ESTA_CONTRASENA"
HIPS_DB_HOST="127.0.0.1"

HIPS_ADMIN_EMAIL="ile@localhost"
HIPS_SENDMAIL_PATH="/usr/sbin/sendmail"

HIPS_WEB_SECRET_KEY="CAMBIAR_ESTA_CLAVE"
HIPS_WEB_PASSWORD="CAMBIAR_ESTA_CONTRASENA"
```

> Las credenciales reales no deben publicarse en capturas, documentación ni repositorios.

El repositorio incluye una plantilla lista para copiar en `config/hips.env.example`, con placeholders para cada variable sensible:

```bash
cp config/hips.env.example /etc/hips/hips.env
sudo chmod 600 /etc/hips/hips.env
```

---

## 6. Base de datos

El proyecto utiliza PostgreSQL como base de datos obligatoria.

Base de datos:

```text
hips_db
```

Usuario de aplicación:

```text
hips_app
```

Tablas principales:

```text
alarmas
acciones_prevencion
baseline_archivos
configuracion_modulos
eventos_sistema
usuarios_web
```

Verificación de tablas:

```bash
sudo -u postgres psql -d hips_db -c "\dt"
```

Verificación de configuración de módulos:

```bash
sudo -u postgres psql -d hips_db -c "
SELECT modulo, habilitado, intervalo_segundos, umbral, configuracion
FROM configuracion_modulos
ORDER BY modulo;"
```

---

## 7. Módulos implementados

### 7.0 Núcleo del sistema (`core/`)

El núcleo separa la orquestación general de la persistencia y la notificación, para que cada pieza se pueda probar de forma aislada.

- **`core/runner.py`**: orquesta la ejecución de todos los módulos de detección en cada corrida del HIPS.
- **`core/engine.py`**: motor de decisión que agrupa las alertas y decide qué acciones preventivas corresponden.
- **`core/alert_service.py`**: normaliza la severidad de cada alerta, extrae metadatos (IP de origen, módulo, tipo) y las envía a `db/repository.py` para su persistencia en `alarmas` y `eventos_sistema`.
- **`core/email_notifier.py`**: construye y envía el correo de notificación al administrador usando `sendmail`, agrupando las alertas por módulo.
- **`core/hips_logger.py`**: logger central que escribe en `/var/log/hips/` con el formato obligatorio de alarmas.

---

### 7.1 Integridad de archivos

Verifica archivos críticos y binarios del sistema contra un baseline seguro.

Archivos incluidos en el baseline:

```text
/etc/passwd
/etc/shadow
/etc/sudoers
/etc/ssh/sshd_config
/bin/bash
/bin/sh
/usr/bin/sudo
/usr/bin/su
/usr/bin/passwd
/usr/bin/ssh
/usr/sbin/sshd
/usr/bin/systemctl
/usr/bin/firewall-cmd
/usr/bin/python3
```

**Almacenamiento del baseline (`detection/file_integrity.py`):** `guardar_baseline()` y `cargar_baseline()` aceptan un destino `db://baseline_archivos` y, cuando se usa, persisten cada ruta con su hash SHA-256 en la tabla `baseline_archivos` de PostgreSQL en lugar de un archivo plano en disco. Esta es la modalidad usada en producción (`core/runner.py` la referencia por defecto). El archivo `config/baseline_archivos.json` solo se conserva como *fallback* para desarrollo local o para cuando la base de datos no está disponible, y como respaldo de migración vía `migrar_baseline_json_a_db()`.

Detecta:

- Modificación de binarios.
- Modificación de `/etc/passwd`.
- Modificación de `/etc/shadow`.
- Diferencia entre hash actual y hash original.

Acción preventiva:

```text
documentar_integridad_archivo
```

---

### 7.2 Usuarios conectados

Verifica usuarios conectados, terminal utilizada y origen de la sesión.


Comandos de apoyo:

```bash
who -uH
w -i
last -ai | head
```

Detecta:

- Usuario conectado desde origen no permitido.
- Login fuera de horario esperado.
- Sesiones sospechosas.

Acciones preventivas:

```text
bloquear_usuario
bloquear_ip
```

---

### 7.3 Sniffers y modo promiscuo

Detecta interfaces en modo promiscuo y herramientas de captura en ejecución.

Herramientas detectadas:

```text
tcpdump
wireshark
ethereal
tshark
dumpcap
```

Detecta:

- Interfaz en modo promiscuo.
- Procesos asociados a sniffers.
- Herramientas de captura activas.

Acción preventiva:

```text
finalizar_proceso
desactivar_modo_promiscuo
```

---

### 7.4 Análisis de logs

Analiza logs del sistema buscando patrones de acceso indebido.

Logs revisados:

```text
/var/log/secure
/var/log/messages
/var/log/httpd/access.log
/var/log/maillog
```

Detecta:

- `Failed password`
- `Authentication failure`
- Fallos de `sudo`
- Errores HTTP repetidos desde una misma IP
- Posible scanner web
- Envío masivo de correos

Acciones preventivas:

```text
bloquear_ip
bloquear_usuario
cambiar_password_usuario
reiniciar_postfix
```

---

### 7.5 Cola de correo

Verifica el tamaño de la cola de correo y detecta comportamientos anómalos.

Comandos de apoyo:

```bash
mailq
postqueue -p
```

Detecta:

- Envío masivo de correos.
- Correos diferidos.
- Error de conexión del servicio de correo.
- Cola de correo fuera del umbral definido.

Acciones preventivas:

```text
bloquear_usuario
reiniciar_postfix
```

---

### 7.6 Procesos con alto consumo

Monitorea procesos con alto consumo de memoria.

Comando de apoyo:

```bash
ps aux --sort=-%mem | head
```

Detecta:

- Procesos con memoria alta.
- Procesos con consumo anómalo sostenido.
- Diferencia entre proceso normal y anómalo.

Criterios configurables:

```text
umbral
intervalo_segundos
tiempo_excesivo_segundos
```

Acción preventiva:

```text
finalizar_proceso
```

---

### 7.7 Directorio `/tmp`

Detecta archivos sospechosos ubicados en `/tmp`.

Detecta:

- Scripts ejecutables.
- Archivos ocultos.
- Extensiones sospechosas.
- Nombres sospechosos.
- Archivos temporales potencialmente maliciosos.

Acción preventiva:

```text
cuarentenar_archivo
archivo_ya_prevenido
```

Directorio de cuarentena:

```text
/var/quarantine/
```

---

### 7.8 Ataques DDoS

Detecta patrones compatibles con DDoS sobre conexiones de red y sobre logs de consultas DNS.

**Conexiones de red (`detectar_conexiones_excesivas`)**: agrupa conexiones activas por IP de origen (salida tipo `ss`/`netstat`) y genera alerta cuando una misma IP supera el umbral configurado.

**Flood de consultas DNS (`detectar_dns_query_flood`, `detection/ddos_monitor.py`)**: parsea logs estilo BIND/`named` (`client <IP>#<puerto> (...): query: ...`), cuenta consultas por IP dentro del log recibido y genera una alerta `dns_query_flood` cuando una IP supera el umbral (`umbral_dns`, 50 por defecto). Es el módulo pensado específicamente para calibrarse con la muestra de log DNS que provee la cátedra.

Detecta:

```text
dns_query_flood
posible_syn_flood
```

Acción preventiva:

```text
bloquear_ip
```

Verificación de reglas:

```bash
sudo firewall-cmd --list-rich-rules
sudo firewall-cmd --list-all
```

> Nota técnica: `detectar_dns_query_flood` está duplicada dentro de `detection/ddos_monitor.py` (dos definiciones idénticas). No rompe nada porque Python se queda con la última, pero conviene limpiarla antes de la entrega para prolijidad del código.

---

### 7.9 Archivos cron

Examina tareas programadas del sistema.

Ubicaciones revisadas:

```text
/etc/crontab
/etc/cron.d/
/etc/cron.hourly/
/etc/cron.daily/
/etc/cron.weekly/
/etc/cron.monthly/
/var/spool/cron/
```

Detecta:

- Cron configurado cada minuto.
- Cron que referencia `/tmp`.
- Rutas sospechosas.
- Nombres sospechosos.

---

### 7.10 Accesos no válidos

Detecta intentos de autenticación fallidos y patrones de credential stuffing.

Detecta:

```text
multiples_intentos_fallidos
credential_stuffing
sudo_fallido
```

Acciones preventivas:

```text
bloquear_ip
bloquear_usuario
cambiar_password_usuario
```

---

## 8. Acciones preventivas implementadas

El sistema registra y ejecuta acciones preventivas asociadas a las alarmas detectadas.

Acciones principales:

```text
bloquear_ip
bloquear_usuario
cambiar_password_usuario
finalizar_proceso
cuarentenar_archivo
reiniciar_postfix
documentar_integridad_archivo
```

Consulta de acciones:

```bash
sudo -u postgres psql -d hips_db -c "
SELECT a.id, a.tipo_alarma, a.modulo, a.descripcion, a.resuelta,
       ap.accion, ap.resultado
FROM alarmas a
JOIN acciones_prevencion ap ON ap.alarma_id = a.id
ORDER BY a.id DESC
LIMIT 10;"
```

---

## 9. Bitácoras

Directorio principal:

```text
/var/log/hips/
```

Archivos generados:

```text
alarmas.log
prevencion.log
prevencion_email.log
alarmas_detalle.jsonl
```

Verificación:

```bash
sudo ls -ld /var/log/hips
sudo ls -l /var/log/hips
sudo tail -n 20 /var/log/hips/alarmas.log
sudo tail -n 20 /var/log/hips/prevencion.log
```

---

## 10. Notificaciones por email

El HIPS envía correos al administrador por:

- Alarmas detectadas.
- Acciones preventivas ejecutadas.

Verificación local:

```bash
sudo grep -iE 'HIPS|Alerta|PREVENCION|bloquear_ip|cuarentenar' /var/spool/mail/ile | tail -n 40
sudo tail -n 20 /var/log/hips/prevencion_email.log
```

---

## 11. Interfaz web

La interfaz web permite:

- Login con usuario y contraseña.
- Revisión de alertas desde dashboard.
- Visualización de acciones preventivas.
- Configuración de módulos.
- Edición de intervalos, umbrales y configuración adicional.

URL local:

```text
http://127.0.0.1:5000/login
```

Verificación:

```bash
systemctl is-active hips-web.service
curl -s -o /dev/null -w "HTTP_CODE=%{http_code}\n" http://127.0.0.1:5000/login
```

---

## 12. Servicios systemd

Servicios utilizados:

```text
hips.service
hips.timer
hips-web.service
```

El repositorio mantiene dos variantes de las unidades systemd:

- **`config/systemd/`**: versión genérica/portable, pensada para instalarse en `/opt/hips-so2` con variables tomadas únicamente de `EnvironmentFile`.
- **`deploy/systemd/`**: versión usada en el despliegue real sobre el servidor de pruebas (`/home/ile/hips-so2`), con variables adicionales en línea y dependencias explícitas de `postfix.service` y `firewalld.service`.

Además, `scripts/run_hips_once.sh` permite ejecutar una corrida manual del HIPS sin depender de systemd:

```bash
chmod +x scripts/run_hips_once.sh
./scripts/run_hips_once.sh
```

Verificación:

```bash
systemctl status hips.service --no-pager
systemctl status hips.timer --no-pager
systemctl status hips-web.service --no-pager
```

Ejecución manual:

```bash
cd /home/ile/hips-so2

sudo env HIPS_DB_NAME="hips_db" \
HIPS_DB_USER="hips_app" \
HIPS_DB_PASSWORD="$(sudo grep '^HIPS_DB_PASSWORD=' /etc/hips/hips.env | cut -d= -f2-)" \
HIPS_DB_HOST="127.0.0.1" \
PYTHONPATH="$PWD" \
python3 hips.py --guardar-db --prevenir --json
```

---

## 13. Hardening aplicado

### Sistema operativo

- Rocky Linux actualizado.
- SELinux en modo enforcing.
- Firewall activo.
- SSH restringido.
- Servicios innecesarios deshabilitados.
- Banner legal configurado.
- `auditd` activo.
- Permisos restrictivos en archivos críticos.
- Usuario dedicado para el HIPS.
- Logs protegidos en `/var/log/hips/`.

### PostgreSQL

- Usuario `hips_app` sin superusuario.
- Permisos restringidos sobre `hips_db`.
- `password_encryption = scram-sha-256`.
- `listen_addresses` restringido.
- Logs de conexión y desconexión habilitados.
- `pg_hba.conf` restringido.
- Configuración de módulos almacenada en base de datos.
- Sin contraseñas reales expuestas en código fuente.

---

## 14. Pruebas realizadas

Se realizaron pruebas controladas para validar cada módulo:

- Modificación de binarios contra baseline.
- Modificación de `/etc/passwd`.
- Modificación de `/etc/shadow`.
- Login desde origen inusual.
- Login fuera de horario.
- Detección de `tcpdump`, `wireshark` y `ethereal`.
- Interfaz en modo promiscuo.
- Fallos de autenticación.
- Scanner HTTP por errores 404 repetidos.
- Envío masivo de correos.
- Cola de correo.
- Procesos con alto consumo de memoria.
- Archivos sospechosos en `/tmp`.
- DDoS DNS.
- Cron sospechoso.
- Credential stuffing.
- Notificación por correo.
- Dashboard web.

Cada prueba deja evidencia en:

```text
PostgreSQL
/var/log/hips/
dashboard web
correo local del administrador
```

Además de las pruebas reales controladas, el proyecto cuenta con una suite de pruebas automatizadas en `tests/` (ejecutable con `pytest`) que cubre, entre otros:

```text
core/alert_service.py      → tests/test_alert_service.py
core/email_notifier.py     → tests/test_email_notifier.py
core/hips_logger.py        → tests/test_hips_logger.py
core/runner.py             → tests/test_runner.py
db/repository.py           → tests/test_db_repository.py
detection/*.py             → tests/test_<modulo>.py
prevention/actions.py      → tests/test_prevention_actions.py
prevention/engine.py       → tests/test_prevention_engine.py
web/app.py                 → tests/test_web_app.py
hips.py (CLI)               → tests/test_hips_cli.py
```

Ejecución:

```bash
pytest tests/ -v
```

> **Nota:** `detectar_dns_query_flood` (DDoS) y el almacenamiento del baseline en PostgreSQL (`db://baseline_archivos`) todavía no tienen tests unitarios propios en `tests/` — por ahora están validados únicamente mediante las pruebas reales de `scripts/demo_maestra.sh` contra el servidor real. Conviene sumarles unit tests antes de la entrega para mantener la cobertura pareja con el resto de los módulos.

### Escenario de pruebas completo (`scripts/demo_maestra.sh`)

Para cumplir con el punto 7 del enunciado ("el grupo debe tener preparado todo el escenario de pruebas para el día de la entrega"), el repositorio incluye un script único que ejecuta, en orden y con narración paso a paso, **todos** los disparadores de los 10 módulos de detección más los controles de hardening del sistema operativo y de PostgreSQL:

```bash
chmod +x scripts/demo_maestra.sh scripts/limpiar_demo_maestra.sh
HIPS_PROYECTO_DIR=/home/ile/hips-so2 ./scripts/demo_maestra.sh
```

El script:

- Verifica los 10+ controles de hardening de Rocky Linux y los 7+ de PostgreSQL (Parte 1 y 2).
- Dispara un evento real por cada módulo (integridad, usuarios, sniffers, logs, cola de correo, procesos, `/tmp`, DDoS/DNS, cron, credential stuffing) y corre un ciclo real del HIPS (`python3 hips.py --guardar-db --prevenir --json`) después de cada uno.
- Consulta PostgreSQL para mostrar la alarma generada y la acción de prevención asociada (`JOIN` entre `alarmas` y `acciones_prevencion`).
- Verifica el email recibido por el administrador (`/var/spool/mail/ile`) tanto para alarmas como para acciones de prevención.
- Verifica el dashboard web y el formato obligatorio de `alarmas.log` (`dd/mm/yyyy :: TIPO :: IP`).

Una vez terminada la demo, `scripts/limpiar_demo_maestra.sh` revierte todo lo simulado: mata procesos de sniffers falsos, borra archivos de `/tmp` y tareas cron de prueba, limpia los logs usados como entrada, quita las IPs de prueba bloqueadas en `firewalld`, elimina usuarios temporales si los hubo, y vuelve a levantar `hips.timer` y `postfix`.

La evidencia completa (capturas, salidas de comandos y checklist de los 17 controles de hardening) está documentada en `EVIDENCIAS, CAPTURAS Y CHECKLIST- HIPS PONT-SANABRIA.pdf`, en la raíz del repositorio.

---

## 15. Consultas útiles

Últimas alarmas:

```bash
sudo -u postgres psql -d hips_db -c "
SELECT id, timestamp, tipo_alarma, modulo, severidad, ip_origen, descripcion, resuelta
FROM alarmas
ORDER BY id DESC
LIMIT 10;"
```

Últimas acciones:

```bash
sudo -u postgres psql -d hips_db -c "
SELECT a.id, a.tipo_alarma, a.modulo, ap.accion, ap.resultado
FROM alarmas a
JOIN acciones_prevencion ap ON ap.alarma_id = a.id
ORDER BY a.id DESC
LIMIT 10;"
```

Configuración de módulos:

```bash
sudo -u postgres psql -d hips_db -c "
SELECT modulo, habilitado, intervalo_segundos, umbral, configuracion
FROM configuracion_modulos
ORDER BY modulo;"
```

Reglas de firewall:

```bash
sudo firewall-cmd --list-all
sudo firewall-cmd --list-rich-rules
```

---

## 16. Historial de desarrollo

El proyecto fue desarrollado de forma incremental utilizando Git y GitHub.

### 16.1 Resumen por fecha

#### 7 de julio de 2026

- Estructura inicial del proyecto.
- Documentación inicial del stack.
- Hardening de Rocky Linux y PostgreSQL.
- Esquema inicial de base de datos.
- Logger central del HIPS.
- Módulos iniciales de detección.
- Acciones preventivas.
- Configuración de módulos en base de datos.
- Repositorio de persistencia.

#### 8 de julio de 2026

- Integración con PostgreSQL.
- Servicio central de alertas.
- Orquestador de alertas.
- Runner principal.
- Comando principal del HIPS.
- Reducción de falsos positivos.
- Servicio periódico con systemd.
- Dashboard web real.
- Notificaciones por email.
- Formato obligatorio de alarmas.
- Configuración de módulos desde dashboard.
- Resolución de alarmas desde dashboard.
- Automatización de acciones preventivas.
- Manual de instalación y uso.
- Documentación de pruebas reales.

#### 9 de julio de 2026

- Mejora de prevención automática.
- Deduplicación de alarmas.
- Corrección de acciones preventivas duplicadas.
- Configuración de horarios permitidos de usuarios.
- Aplicación de módulos habilitados y umbrales al runner.
- Servicio automático del dashboard web.
- Corrección de eventos duplicados.

#### 10 de julio de 2026

- Detección web.
- Refuerzo de manejo de secretos.
- Scanner HTTP.
- Detección de credential stuffing.

#### 12 de julio de 2026

- Separación del servicio central de alertas (`core/alert_service.py`) como capa independiente entre los módulos de detección y la base de datos.
- Notificador de email dedicado (`core/email_notifier.py`), desacoplado del runner principal.
- Módulos de detección movidos a archivos independientes: `file_integrity.py`, `mail_queue.py`, `sniffers.py`.
- Plantilla de variables de entorno (`config/hips.env.example`) para facilitar la instalación.
- Unidades systemd de despliegue real (`deploy/systemd/`) además de la versión portable (`config/systemd/`).
- Script de ejecución manual (`scripts/run_hips_once.sh`).
- Suite de pruebas ampliada: cobertura para el servicio de alertas, el notificador de email, el repositorio de base de datos, el runner, el CLI del HIPS y el dashboard web.
- Documentación adicional en `docs/`: manual de instalación y uso, matriz de módulos y prevención, hardening de Rocky Linux y PostgreSQL, y evidencias de pruebas reales por módulo.
- Detección de flood de consultas DNS (`detectar_dns_query_flood` en `detection/ddos_monitor.py`), calibrada contra logs estilo BIND/`named`, para cubrir la muestra de log DNS que provee la cátedra.
- Almacenamiento del baseline de integridad en PostgreSQL (`db://baseline_archivos`), con `config/baseline_archivos.json` como respaldo local únicamente.
- Script de demo integral (`scripts/demo_maestra.sh`) que ejecuta los 10 módulos de detección, el hardening de Rocky Linux y de PostgreSQL, y valida notificaciones y dashboard en un solo escenario ordenado, más su contraparte de limpieza (`scripts/limpiar_demo_maestra.sh`).
- Evidencia consolidada de hardening y pruebas reales en `EVIDENCIAS, CAPTURAS Y CHECKLIST- HIPS PONT-SANABRIA.pdf`.

---

## 17. Contribuciones por integrante

### Ileana Sanabria (`ilean01`)

Aportes principales:

- Estructura inicial del proyecto.
- Módulos de detección.
- Acciones preventivas.
- Dashboard web.
- Notificaciones por correo.
- Servicios systemd.
- Pruebas y correcciones.
- Documentación técnica.
- Servicio central de alertas (`core/alert_service.py`).
- Notificador de email dedicado (`core/email_notifier.py`).
- Separación de los módulos de detección en archivos independientes (`file_integrity.py`, `mail_queue.py`, `sniffers.py`).
- Plantilla de variables de entorno (`config/hips.env.example`).
- Unidades systemd de despliegue real (`deploy/systemd/`) y script de ejecución manual (`scripts/run_hips_once.sh`).
- Ampliación de la suite de pruebas automatizadas.

Commits destacados:

```text
chore(project): estructura inicial del proyecto HIPS
feat(core): agregar logger central HIPS
feat(detection): agregar modulo de integridad de archivos
feat(detection): agregar deteccion de intentos fallidos de login
feat(detection): agregar deteccion de sniffers
feat(detection): agregar monitoreo de procesos sospechosos
feat(detection): agregar monitoreo de usuarios
feat(detection): agregar analisis de logs del sistema
feat(detection): agregar monitoreo de tmp
feat(detection): agregar monitoreo de cron
feat(detection): agregar monitoreo de cola de correo
feat(detection): agregar monitoreo de ddos
feat(prevention): agregar acciones preventivas
feat(web): agregar dashboard real de alertas
feat(notification): agregar email al administrador
feat(systemd): agregar servicio periodico del HIPS
feat(detection): agregar scanner HTTP y credential stuffing
feat(security): agregar deteccion web y reforzar secretos
```

### Elias Pont (`eliasleonardo11-dotcom`)

Aportes principales:

- Integración con PostgreSQL.
- Repositorio de persistencia.
- Servicio central de alertas.
- Orquestador de alertas.
- Configuración de módulos desde dashboard.
- Resolución de alarmas.
- Hardening y documentación.
- Corrección de duplicados y falsos positivos.
- Monitoreo real de usuarios conectados.
- Manual de instalación y uso.

Commits destacados:

```text
docs(db): documentar integracion PostgreSQL
feat(db): agregar conexion a PostgreSQL
feat(db): agregar repositorio para persistencia
feat(core): agregar servicio central de alertas
feat(core): agregar orquestador de alertas
docs(core): documentar ejecucion real del HIPS
fix(detection): reducir falsos positivos reales
feat(detection): agregar monitoreo real de usuarios conectados
docs(test): documentar pruebas reales de modulos
fix(logging): aplicar formato obligatorio de alarmas
feat(web): permitir resolver alarmas desde dashboard
feat(web): permitir configurar modulos desde dashboard
docs: agregar manual de instalacion y uso
feat(web): configurar horarios permitidos de usuarios
fix(prevention): no bloquear usuarios nuevos automaticamente
fix(prevention): evitar acciones preventivas duplicadas
feat(config): aplicar modulos habilitados y umbrales al runner
fix(events): evitar eventos de alerta duplicados
```

---

## 18. Seguridad y buenas prácticas

- No guardar contraseñas reales en el código fuente.
- Usar variables de entorno para secretos.
- No publicar capturas con credenciales visibles.
- Ejecutar servicios con usuarios dedicados.
- Restringir permisos sobre logs y archivos sensibles.
- Mantener PostgreSQL limitado a conexiones locales.
- Registrar alarmas y acciones preventivas.
- Validar falsos positivos antes de aplicar acciones destructivas.
- Documentar cada prueba con evidencia.

---

## 19. Estado del proyecto

El sistema HIPS cuenta con módulos de detección, prevención, bitácoras, base de datos, correo y dashboard web.  
El proyecto fue probado en un entorno controlado de Rocky Linux y se encuentra preparado para demostración académica.

---

## 20. Autores

- **Ileana Sanabria** ([`ilean01`](https://github.com/ilean01))
- **Elias Pont** ([`eliasleonardo11-dotcom`](https://github.com/eliasleonardo11-dotcom))

Proyecto desarrollado para la materia **Sistemas Operativos 2**, Universidad Católica Nuestra Señora de la Asunción (UC).
