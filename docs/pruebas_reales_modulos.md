# Pruebas reales controladas de módulos HIPS

Este documento registra las pruebas reales realizadas sobre Rocky Linux para demostrar que los módulos del HIPS no funcionan solamente con datos simulados.

Todas las pruebas fueron ejecutadas sobre el sistema real y las alertas fueron persistidas en PostgreSQL usando la base `hips_db` y el usuario de aplicación `hips_app`.

---

## Resumen de módulos comprobados

| Módulo | Estado | Evidencia |
|---|---|---|
| Directorio /tmp | Real controlado | Se creó un script real en `/tmp` y el HIPS detectó archivo ejecutable y extensión sospechosa |
| Cron | Real controlado | Se creó una entrada real en `/etc/cron.d/` apuntando a `/tmp` |
| Integridad de archivos | Real controlado | Se creó baseline de un archivo real en `/etc` y luego se modificó |
| Procesos con alto consumo | Real controlado | Se lanzó un proceso real Python con CPU alta |
| Sniffers | Real controlado | Se ejecutó `tcpdump` real y el HIPS lo detectó |
| DDoS / muchas conexiones | Real controlado | Se levantó un servidor local y se abrieron muchas conexiones reales |
| Usuarios conectados | Real controlado | Se leyó la salida real de `who` |
| Cola de correo | Real controlado | Se instaló Postfix, se generaron 25 correos reales y quedaron en `mailq` |

---

## 1. Directorio /tmp

### Acción realizada

Se creó un archivo real en `/tmp`:

`/tmp/hips_real_tmp_test.sh`

El archivo fue marcado como ejecutable.

### Resultado detectado por HIPS

El módulo `tmp_monitor` detectó:

- `extension_sospechosa_tmp`
- `ejecutable_en_tmp`

### Evidencia en PostgreSQL

Se guardaron alertas en la tabla `alarmas`:

- `extension_sospechosa_tmp`
- `ejecutable_en_tmp`

### Conclusión

El módulo `/tmp` funciona con archivos reales del sistema.

---

## 2. Cron sospechoso

### Acción realizada

Se creó una entrada real en:

`/etc/cron.d/hips_real_cron_test`

Contenido usado:

`0 0 31 2 * root /tmp/hips_cron_test.sh`

La fecha 31 de febrero fue usada para evitar ejecución real, pero dejando una entrada real legible por el HIPS.

### Resultado detectado por HIPS

El módulo `cron_monitor` detectó:

- `ejecucion_tmp_cron`

### Evidencia en PostgreSQL

Alerta registrada:

- id: 11
- tipo_alarma: `ejecucion_tmp_cron`
- modulo: `cron_monitor`
- descripcion: `Cron ejecuta o referencia archivos temporales`

### Conclusión

El módulo de cron funciona leyendo archivos reales de `/etc/cron.d`.

---

## 3. Integridad de archivos

### Acción realizada

Se creó un archivo real en `/etc`:

`/etc/hips_integrity_test.conf`

Primero contenía:

`estado=original`

Luego se generó baseline en:

`config/baseline_archivos.json`

Después el archivo fue modificado a:

`estado=modificado`

### Resultado detectado por HIPS

El módulo `integridad_archivos` detectó:

- `archivo_modificado`

### Evidencia en PostgreSQL

Alerta registrada:

- id: 12
- tipo_alarma: `archivo_modificado`
- modulo: `integridad_archivos`
- descripcion: `El archivo /etc/hips_integrity_test.conf fue modificado`

### Conclusión

El módulo de integridad funciona comparando hashes reales de archivos reales.

---

## 4. Procesos con alto consumo

### Acción realizada

Se lanzó un proceso real de CPU alta:

`python3 -c "while True: pass"`

Luego se verificó con `ps` que consumía cerca de 99% de CPU.

### Resultado detectado por HIPS

El módulo `process_monitor` detectó:

- `cpu_alta`

### Evidencia en PostgreSQL

Alerta registrada:

- id: 15
- tipo_alarma: `cpu_alta`
- modulo: `process_monitor`
- descripcion: `Proceso con CPU alta: 99.5%`

### Conclusión

El módulo de procesos funciona leyendo procesos reales del sistema.

---

## 5. Sniffers

### Acción realizada

Se ejecutó `tcpdump` real en loopback:

`sudo timeout 60 /usr/sbin/tcpdump -i lo -w /tmp/hips_tcpdump_test.pcap`

Luego se verificó con `ps` que el proceso estaba activo.

### Resultado detectado por HIPS

El módulo `sniffers` detectó:

- `sniffer_detectado`

Después se corrigió el detector para evitar duplicados generados por wrappers como `sudo` y `timeout`.

### Evidencia en PostgreSQL

Alerta registrada luego de la corrección:

- id: 22
- tipo_alarma: `sniffer_detectado`
- modulo: `sniffers`
- descripcion: `Se detectó posible sniffer activo: tcpdump`

### Conclusión

El módulo de sniffers funciona con herramientas reales como `tcpdump`.

---

## 6. DDoS / muchas conexiones

### Acción realizada

Se levantó un servidor local real:

`python3 -m http.server 8088 --bind 127.0.0.1`

Luego se abrieron múltiples conexiones reales contra el puerto `8088`.

### Resultado detectado por HIPS

El módulo `ddos_monitor` detectó:

- `muchas_conexiones_desde_ip`

### Evidencia en PostgreSQL

Alerta registrada:

- id: 24
- tipo_alarma: `muchas_conexiones_desde_ip`
- modulo: `ddos_monitor`
- descripcion: `Se detectaron 87 conexiones desde la IP 127.0.0.1`

### Conclusión

El módulo DDoS funciona detectando muchas conexiones reales desde una misma IP.

---

## 7. Usuarios conectados

### Acción realizada

Se leyó la salida real del comando:

`who`

Resultado real observado:

`ile tty2 2026-07-08 14:00 (local)`

Para generar una alerta controlada, se ejecutó el detector con una política temporal sin orígenes permitidos.

### Resultado detectado por HIPS

El módulo `user_monitor` detectó:

- `origen_login_inusual`

### Evidencia en PostgreSQL

Alerta registrada:

- id: 25
- tipo_alarma: `origen_login_inusual`
- modulo: `user_monitor`
- descripcion: `Usuario conectado desde origen no permitido: local`

### Conclusión

El módulo de usuarios conectados funciona usando sesiones reales del sistema.

---

## 8. Cola de correo

### Acción realizada

Primero se comprobó que no existía `mailq`, `postfix` ni `sendmail`.

Luego se instaló Postfix y se configuró una prueba controlada:

- `inet_interfaces = loopback-only`
- `relayhost = [127.0.0.1]:2525`

Esto hizo que los correos no salieran a internet y quedaran diferidos en la cola real.

Se generaron 25 correos reales con `sendmail`.

### Resultado detectado por HIPS

El módulo `mail_queue` detectó:

- `cola_correo_alta`
- `error_conexion_correo`

### Evidencia en PostgreSQL

Alertas registradas:

- id: 26
- tipo_alarma: `cola_correo_alta`
- modulo: `mail_queue`
- descripcion: `La cola de correo tiene 25 mensajes pendientes`

- id: 27
- tipo_alarma: `error_conexion_correo`
- modulo: `mail_queue`
- descripcion: `Se detectaron errores de conexión en la cola de correo`

### Limpieza realizada

Se limpió la cola con:

`sudo postsuper -d ALL`

Resultado:

`postsuper: Deleted: 25 messages`

Luego se verificó:

`Mail queue is empty`

También se restauró la configuración original de Postfix.

### Conclusión

El módulo de cola de correo funciona usando una cola real de Postfix.

---

## Conclusión general

Los siguientes módulos fueron comprobados con pruebas reales controladas sobre Rocky Linux:

- integridad de archivos
- usuarios conectados
- sniffers
- análisis de procesos
- directorio `/tmp`
- ataques DDoS por muchas conexiones
- cron sospechoso
- cola de correo

Las pruebas no fueron únicamente simuladas: se crearon condiciones reales y controladas en el sistema, el HIPS las detectó y las alertas fueron guardadas en PostgreSQL.
