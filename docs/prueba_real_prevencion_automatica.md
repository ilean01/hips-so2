# Prueba real de prevención automática

Este documento registra una prueba real del HIPS funcionando de forma automática con systemd timer.

## Objetivo

Comprobar que el HIPS puede:

- ejecutarse automáticamente con systemd
- detectar un sniffer real
- guardar la alarma en PostgreSQL
- enviar email al administrador
- ejecutar una acción de prevención real
- marcar la alarma como resuelta automáticamente cuando la prevención fue exitosa

## Configuración automática

El servicio systemd ejecuta:

    python3 hips.py --guardar-db --enviar-email --prevenir --json

El timer ejecuta el servicio periódicamente.

## Prueba realizada

Se levantó un sniffer real controlado con tcpdump:

    sudo timeout 180 /usr/sbin/tcpdump -i lo -w /tmp/hips_sniffing_auto2.pcap

Luego se esperó a que el timer ejecutara el HIPS automáticamente.

## Resultado

El HIPS detectó el sniffer y ejecutó prevención real.

Resultado observado:

    tcpdump fue finalizado automaticamente por HIPS

Alarma registrada en PostgreSQL:

    id: 36
    tipo_alarma: sniffer_detectado
    modulo: sniffers
    severidad: MEDIA
    descripcion: Se detectó posible sniffer activo: tcpdump
    resuelta: true

Evento registrado:

    modulo: prevention_engine
    evento: alarma_resuelta_automaticamente
    detalle: Alarma 36 marcada como resuelta automáticamente por prevención

Acción registrada en prevencion.log:

    evento: finalizar_proceso
    pid: 33164
    dry_run: false
    ejecutado: true

## Conclusión

La prueba fue exitosa.

El HIPS no dependió de una ejecución manual. El timer ejecutó el sistema automáticamente, el módulo de sniffers detectó tcpdump, el motor de prevención finalizó el proceso real y la alarma quedó resuelta automáticamente.
