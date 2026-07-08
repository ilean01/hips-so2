# Servicio systemd para HIPS

Este documento explica cómo dejar el HIPS ejecutándose periódicamente en Rocky Linux usando systemd.

## Archivos creados

- config/systemd/hips.service
- config/systemd/hips.timer
- scripts/run_hips_once.sh
- config/hips.env.example

## Objetivo

Permitir que el sistema HIPS se ejecute automáticamente cada cierto tiempo y guarde alertas reales en PostgreSQL.

## Preparar instalación en el sistema

Copiar el proyecto a /opt:

cp -r /home/ile/hips-so2 /opt/hips-so2

Crear carpeta de configuración:

sudo mkdir -p /etc/hips

Crear archivo de entorno:

sudo cp /opt/hips-so2/config/hips.env.example /etc/hips/hips.env

Editar el archivo y poner la contraseña real de hips_app:

sudo nano /etc/hips/hips.env

Proteger el archivo:

sudo chown root:root /etc/hips/hips.env
sudo chmod 600 /etc/hips/hips.env

## Instalar unidades systemd

Copiar los archivos:

sudo cp /opt/hips-so2/config/systemd/hips.service /etc/systemd/system/hips.service
sudo cp /opt/hips-so2/config/systemd/hips.timer /etc/systemd/system/hips.timer

Recargar systemd:

sudo systemctl daemon-reload

Activar el timer:

sudo systemctl enable --now hips.timer

Verificar estado:

sudo systemctl status hips.timer
sudo systemctl list-timers | grep hips

## Ejecutar manualmente una vez

sudo systemctl start hips.service

## Ver logs del servicio

journalctl -u hips.service -n 50 --no-pager

## Conclusión

Con este timer, el HIPS puede ejecutarse de forma periódica y guardar alertas en PostgreSQL sin intervención manual.
