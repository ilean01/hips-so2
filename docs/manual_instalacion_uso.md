# Manual de instalación y uso del HIPS

## Requisitos

El sistema fue probado en Rocky Linux.

Requiere:

- Python 3
- PostgreSQL
- Postfix/sendmail
- Flask
- pip
- systemd
- permisos sudo para algunas pruebas reales

## Instalar dependencias

Desde la carpeta del proyecto ejecutar:

    python3 -m pip install --user -r requirements.txt

## Variables de entorno

Ejemplo de configuración local:

    export HIPS_DB_NAME="hips_db"
    export HIPS_DB_USER="hips_app"
    export HIPS_DB_PASSWORD="CAMBIAR_ESTA_CONTRASENA"
    export HIPS_DB_HOST="127.0.0.1"

    export HIPS_ADMIN_EMAIL="ile@localhost"
    export HIPS_SENDMAIL_PATH="/usr/sbin/sendmail"

    export HIPS_WEB_USER="admin"
    export HIPS_WEB_PASSWORD="CAMBIAR_ESTA_CONTRASENA_WEB"
    export HIPS_WEB_SECRET_KEY="CAMBIAR_ESTA_CLAVE_SECRETA_WEB"

    export PYTHONPATH="$PWD"

## Ejecutar pruebas

Para correr todos los tests:

    python3 -m unittest discover -s tests -p "test_*.py" -v

Resultado esperado:

    OK

## Ejecutar HIPS

Para ejecutar el HIPS una vez:

    sudo env HIPS_DB_NAME="$HIPS_DB_NAME" HIPS_DB_USER="$HIPS_DB_USER" HIPS_DB_PASSWORD="$HIPS_DB_PASSWORD" HIPS_DB_HOST="$HIPS_DB_HOST" HIPS_ADMIN_EMAIL="$HIPS_ADMIN_EMAIL" PYTHONPATH="$PWD" python3 hips.py --guardar-db --enviar-email --json

Este comando:

- ejecuta los módulos de detección
- guarda alertas en PostgreSQL
- escribe logs
- envía email al administrador si hay alertas

## Logs

Los logs se guardan en:

    /var/log/hips/alarmas.log
    /var/log/hips/alarmas_detalle.jsonl
    /var/log/hips/prevencion.log

Formato obligatorio de alarmas:

    dd/mm/yyyy :: TIPO_ALARMA :: IP_ORIGEN

## Dashboard web

Para iniciar la web:

    python3 web/app.py

Luego abrir en el navegador:

    http://127.0.0.1:5000/login

Usuario de prueba:

    admin

Contraseña de prueba:

    CAMBIAR_ESTA_CONTRASENA_WEB

## Funciones del dashboard

El dashboard permite:

- ver alarmas reales
- ver eventos reales
- ver módulos configurados
- marcar alarmas como resueltas
- actualizar configuración de módulos

## Evidencias reales

Las pruebas reales están documentadas en:

    docs/pruebas_reales_modulos.md
    docs/pruebas_reales_prevencion.md
    docs/prueba_real_email.md
    docs/prueba_real_dashboard_web.md

## Funcionalidades implementadas

El HIPS incluye:

- detección de eventos sospechosos
- monitoreo de logs
- monitoreo de /tmp
- monitoreo de cron
- detección de sniffers
- monitoreo de procesos
- monitoreo de usuarios
- detección de muchas conexiones
- monitoreo de cola de correo
- integridad de archivos
- persistencia en PostgreSQL
- logs obligatorios
- prevención real controlada
- email al administrador
- dashboard web con login
- configuración de módulos desde la web
