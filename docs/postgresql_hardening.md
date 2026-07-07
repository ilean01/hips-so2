# Hardening PostgreSQL — HIPS

Sistema: Rocky Linux 9.8  
Base de datos: hips_db  
Usuario de aplicación: hips_app  

Este documento registra los 7 controles de hardening aplicados y verificados en PostgreSQL para el proyecto HIPS.

---

## 1. Usuario de aplicación sin superusuario

Se creó el usuario `hips_app` para que la aplicación no utilice el usuario administrador `postgres`.

Verificación:

SELECT rolname, rolsuper, rolcreaterole, rolcreatedb
FROM pg_roles
WHERE rolname = 'hips_app';

Resultado verificado:

hips_app | f | f | f

Esto confirma que `hips_app` no es superusuario.

---

## 2. Base de datos y tablas propiedad de hips_app

Se creó la base `hips_db` y las tablas quedaron con owner `hips_app`.

Verificación:

sudo -u postgres psql -d hips_db -c "\dt"

Tablas verificadas:

- acciones_prevencion
- alarmas
- baseline_archivos
- configuracion_modulos
- eventos_sistema
- usuarios_web

Todas aparecen con owner `hips_app`.

---

## 3. Contraseñas cifradas con scram-sha-256

Comando aplicado:

sudo -u postgres psql -d hips_db -c "ALTER SYSTEM SET password_encryption = 'scram-sha-256';"

Verificación:

sudo -u postgres psql -d hips_db -c "SHOW password_encryption;"

Resultado verificado:

scram-sha-256

---

## 4. PostgreSQL escuchando solo en localhost

Comando aplicado:

sudo -u postgres psql -d hips_db -c "ALTER SYSTEM SET listen_addresses = 'localhost';"

Verificación:

sudo -u postgres psql -d hips_db -c "SHOW listen_addresses;"

Resultado verificado:

localhost

---

## 5. Registro de conexiones activado

Comando aplicado:

sudo -u postgres psql -d hips_db -c "ALTER SYSTEM SET log_connections = 'on';"

Verificación:

sudo -u postgres psql -d hips_db -c "SHOW log_connections;"

Resultado verificado:

on

---

## 6. Registro de desconexiones activado

Comando aplicado:

sudo -u postgres psql -d hips_db -c "ALTER SYSTEM SET log_disconnections = 'on';"

Verificación:

sudo -u postgres psql -d hips_db -c "SHOW log_disconnections;"

Resultado verificado:

on

---

## 7. Acceso limitado por pg_hba.conf

Se verificó que PostgreSQL no permite conexiones abiertas desde cualquier red.

Verificación:

sudo grep -vE '^\s*#|^\s*$' /var/lib/pgsql/data/pg_hba.conf

Resultado verificado:

local   all          all                    peer
host    all          all    127.0.0.1/32    ident
host    all          all    ::1/128         ident
local   replication  all                    peer
host    replication  all    127.0.0.1/32    ident
host    replication  all    ::1/128         ident

No aparece una regla abierta como `0.0.0.0/0`.

---

## Reinicio del servicio

Después de aplicar los cambios se reinició PostgreSQL.

Comando:

sudo systemctl restart postgresql

Verificación:

sudo systemctl status postgresql

Resultado verificado:

Active: active (running)

---

## Resumen

| # | Control | Estado |
|---|---|---|
| 1 | Usuario `hips_app` sin superusuario | Aplicado |
| 2 | Base y tablas propiedad de `hips_app` | Aplicado |
| 3 | `password_encryption = scram-sha-256` | Aplicado |
| 4 | `listen_addresses = localhost` | Aplicado |
| 5 | `log_connections = on` | Aplicado |
| 6 | `log_disconnections = on` | Aplicado |
| 7 | `pg_hba.conf` limitado a conexiones locales | Aplicado |
