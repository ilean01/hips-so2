# Prueba real de prevención automática contra sniffers

## Objetivo

Comprobar que el HIPS puede detectar y prevenir automáticamente un sniffer real sin intervención manual.

## Servicio automático

El HIPS quedó ejecutándose automáticamente mediante systemd timer.

El servicio usa:

```text
--guardar-db
--enviar-email
--prevenir
--json
