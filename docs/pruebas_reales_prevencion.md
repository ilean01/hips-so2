# Pruebas reales controladas de prevención HIPS

Este documento registra las pruebas reales realizadas para demostrar que las acciones de prevención del HIPS no funcionan solo en modo simulado.

Todas las pruebas fueron ejecutadas con `dry_run=False`, por lo tanto las acciones se aplicaron realmente sobre el sistema de forma controlada.

---

## Resumen

| Acción de prevención | Estado | Evidencia |
|---|---|---|
| Cuarentenar archivo | Real controlado | Se movió un archivo real desde `/tmp` a `/var/quarantine/hips` |
| Finalizar proceso | Real controlado | Se finalizó un proceso real `sleep 300` |
| Bloquear IP | Real controlado | Se agregó una regla real en `firewalld` y luego se eliminó |

---

## 1. Cuarentenar archivo

### Acción realizada

Se creó un archivo real en:

`/tmp/hips_prevencion_test.sh`

Luego se ejecutó la acción:

`cuarentenar_archivo(..., dry_run=False)`

### Resultado

El archivo original dejó de existir en `/tmp`.

El archivo fue movido a:

`/var/quarantine/hips/hips_prevencion_test.sh.1f14947d37e0.quarantine`

### Evidencia del resultado

La acción devolvió:

- accion: `cuarentenar_archivo`
- dry_run: `false`
- ejecutado: `true`
- sha256: `1f14947d37e0b85a44cb4043b0fd927c80b44b310c3f2389454c26aaf4e2076f`

### Evidencia en log

Se registró en:

`/var/log/hips/prevencion.log`

Evento registrado:

`cuarentenar_archivo`

### Conclusión

La acción de cuarentena funciona de forma real porque movió físicamente un archivo del sistema.

---

## 2. Finalizar proceso

### Acción realizada

Se creó un proceso real:

`sleep 300`

El sistema asignó el PID:

`28295`

Luego se ejecutó:

`finalizar_proceso(28295, dry_run=False)`

### Resultado

El proceso fue terminado correctamente.

La terminal mostró:

`Terminado sleep 300`

Y la verificación posterior confirmó:

`proceso de prueba finalizado correctamente`

### Evidencia del resultado

La acción devolvió:

- accion: `finalizar_proceso`
- pid: `28295`
- senal: `15`
- dry_run: `false`
- ejecutado: `true`

### Evidencia en log

Se registró en:

`/var/log/hips/prevencion.log`

Evento registrado:

`finalizar_proceso`

### Conclusión

La acción de finalizar procesos funciona de forma real porque terminó un proceso existente del sistema.

---

## 3. Bloquear IP

### Acción realizada

Primero se verificó que `firewalld` estaba activo:

`running`

Luego se ejecutó:

`bloquear_ip("203.0.113.250", dry_run=False)`

La IP usada pertenece a un rango reservado para documentación, por lo que fue segura para una prueba controlada.

### Resultado

Se agregó una regla real en `firewalld`:

`rule family="ipv4" source address="203.0.113.250" reject`

### Evidencia del resultado

La acción devolvió:

- accion: `bloquear_ip`
- ip: `203.0.113.250`
- dry_run: `false`
- ejecutado: `true`

### Evidencia en log

Se registró en:

`/var/log/hips/prevencion.log`

Evento registrado:

`bloquear_ip`

### Limpieza realizada

Después de la prueba se eliminó la regla con:

`firewall-cmd --permanent --remove-rich-rule`

Luego se recargó firewalld y se confirmó:

`regla de prueba eliminada correctamente`

### Conclusión

La acción de bloqueo de IP funciona de forma real porque agregó una regla efectiva en el firewall del sistema y luego fue limpiada correctamente.

---

## Conclusión general

Las acciones principales de prevención del HIPS fueron comprobadas con pruebas reales controladas:

- mover archivos sospechosos a cuarentena
- finalizar procesos
- bloquear IPs en firewall

Estas pruebas no fueron solamente simuladas. Se ejecutaron acciones reales sobre Rocky Linux con `dry_run=False` y quedaron registradas en `/var/log/hips/prevencion.log`.
