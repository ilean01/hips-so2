# Prueba real de email al administrador

Este documento registra la prueba real de envío de correo del HIPS al administrador.

## Objetivo

Comprobar que cuando el HIPS detecta alertas reales puede:

- guardar alertas en PostgreSQL
- escribir logs
- enviar un correo real al administrador usando Postfix/sendmail

## Configuración usada

Se usó el correo local:

`ile@localhost`

El envío se realizó usando:

`/usr/sbin/sendmail`

Postfix estaba activo y funcionando localmente.

## Prueba realizada

Se creó un archivo sospechoso real en `/tmp`:

`/tmp/hips_email_test.sh`

Luego se ejecutó el HIPS con:

`--guardar-db --enviar-email --json`

También se configuró:

`HIPS_ADMIN_EMAIL=ile@localhost`

## Resultado del HIPS

El HIPS detectó 4 alertas:

- 2 alertas de `system_logs`
- 2 alertas de `tmp_monitor`

Las alertas fueron persistidas en PostgreSQL con IDs:

- system_logs: 31, 32
- tmp_monitor: 33, 34

## Resultado del email

La salida del HIPS confirmó:

- enviado: true
- admin_email: ile@localhost
- sendmail_path: /usr/sbin/sendmail
- returncode: 0
- stderr: vacío

## Verificación de cola de correo

Se ejecutó:

`mailq`

Resultado:

`Mail queue is empty`

Esto indica que el correo no quedó retenido en cola.

## Verificación del buzón local

Se encontró el asunto del correo en el buzón local:

`Subject: [HIPS] 4 alerta(s) detectada(s) en localhost.localdomain`

## Verificación en logs de Postfix

Postfix registró la entrega:

`status=sent (delivered to mailbox)`

## Conclusión

La prueba fue exitosa.

El HIPS envió un correo real al administrador usando Postfix/sendmail.  
Esta funcionalidad no fue simulada.
