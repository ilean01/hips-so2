# Matriz final de módulos, detección, prevención y evidencia

| Módulo | Detección | Prevención automática | Evidencia |
|---|---|---|---|
| system_logs | sudo fallido, servicios fallidos, SELinux denied, OOM, segfault | Bloqueo de IP si la alerta contiene origen remoto | docs/pruebas_reales_modulos.md |
| auth_failures | Intentos fallidos de autenticación y fuerza bruta | Bloqueo de IP con firewalld si la alerta contiene IP | docs/pruebas_reales_modulos.md |
| tmp_monitor | Archivos ejecutables, ocultos, world writable o sospechosos en /tmp | Movimiento a cuarentena en /var/quarantine/hips | docs/pruebas_reales_prevencion.md |
| cron_monitor | Cron cada minuto, reverse shell, descargas remotas o referencias a /tmp | Movimiento a cuarentena si hay archivo identificable | docs/pruebas_reales_modulos.md |
| integridad_archivos | Archivo crítico modificado o eliminado respecto al baseline | Acción preventiva documentada y registro de evento preventivo | docs/pruebas_reales_modulos.md |
| sniffers | Procesos tcpdump, tshark, wireshark, dumpcap, dsniff, snort | Finalización del proceso sospechoso | docs/prueba_real_prevencion_automatica.md |
| sniffers | Interfaz con flag PROMISC en ip link show | Desactivar modo promiscuo con ip link set interfaz promisc off | tests/test_sniffers_promisc.py |
| process_monitor | CPU o memoria alta, netcat, nmap u otros procesos sospechosos | Finalización del proceso si se obtiene PID | docs/pruebas_reales_modulos.md |
| user_monitor | Usuario nuevo, UID 0 no root, UID modificado, shell interactiva agregada, login inusual | Bloqueo del usuario Linux si no está protegido | tests/test_prevention_engine_extra.py |
| mail_queue | Cola alta, correos diferidos, errores, rebotes o posible spam | Limpiar cola diferida, reiniciar Postfix o pausar Postfix según tipo | tests/test_prevention_engine_extra.py |
| ddos_monitor | Muchas conexiones desde la misma IP o posible SYN flood | Bloqueo de IP con firewalld | docs/pruebas_reales_modulos.md |

## Autoarranque

El HIPS se ejecuta automáticamente con systemd:

    hips.timer -> hips.service

El servicio ejecuta:

    python3 hips.py --guardar-db --enviar-email --prevenir --json

## Resultado esperado

Cuando una acción preventiva se ejecuta correctamente:

1. La alarma se guarda en PostgreSQL.
2. La acción se guarda en acciones_prevencion.
3. Se registra evento en eventos_sistema.
4. Se escribe en /var/log/hips/prevencion.log.
5. La alarma queda marcada como resuelta automáticamente.
