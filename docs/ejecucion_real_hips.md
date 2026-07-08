# Ejecución real del HIPS en Rocky Linux

Este documento registra una prueba real del sistema HIPS ejecutándose sobre Rocky Linux y guardando alertas en PostgreSQL.

## Objetivo

Comprobar que el HIPS puede:

- ejecutarse sobre el sistema real
- detectar eventos reales del sistema
- conectarse a PostgreSQL con el usuario de aplicación hips_app
- guardar alertas en la tabla alarmas
- registrar eventos en la tabla eventos_sistema

## Usuario de base de datos usado

El HIPS se conectó a PostgreSQL con el usuario:

hips_app

No se usó el superusuario postgres para la aplicación.

## Comando ejecutado

sudo env HIPS_DB_NAME="hips_db" HIPS_DB_USER="hips_app" HIPS_DB_PASSWORD="$HIPS_DB_PASSWORD" HIPS_DB_HOST="127.0.0.1" PYTHONPATH="$PWD" python3 hips.py --guardar-db --sin-logs --json

## Resultado del HIPS

El sistema detectó 1 alerta real:

- módulo: system_logs
- tipo: sudo_fallido
- cantidad: 1

Resultado de persistencia:

- módulo: system_logs
- cantidad guardada: 1
- id de alarma generado: 2

## Verificación en PostgreSQL

Consulta realizada sobre la tabla alarmas:

id: 2
tipo_alarma: sudo_fallido
modulo: system_logs
severidad: ALTA
ip_origen: vacío
resuelta: false
descripcion: Se detectó un intento fallido de sudo

Consulta realizada sobre la tabla eventos_sistema:

id: 2
modulo: system_logs
evento: alerta_registrada
detalle: Se registró alerta sudo_fallido con id 2

## Conclusión

La prueba fue exitosa.

El HIPS funcionó de forma real porque:

- leyó información del sistema operativo
- detectó un evento real de seguridad
- se conectó a PostgreSQL con hips_app
- insertó la alerta real en la base
- registró el evento asociado en eventos_sistema

Esto demuestra que el proyecto no funciona solo con datos simulados, sino también sobre el sistema real.
