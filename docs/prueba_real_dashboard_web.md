# Prueba real del dashboard web

Este documento registra las pruebas reales realizadas sobre el dashboard web del HIPS.

## Objetivo

Comprobar que la interfaz web puede:

- iniciar sesión con usuario y contraseña
- leer alarmas reales desde PostgreSQL
- leer eventos reales desde PostgreSQL
- leer configuración real de módulos
- marcar alarmas como resueltas
- actualizar configuración de módulos desde la web

## Acceso usado

URL local:

`http://127.0.0.1:5000/login`

Usuario:

`admin`

Contraseña:

`CAMBIAR_ESTA_CONTRASENA_WEB`

## Visualización de datos reales

El dashboard mostró información real almacenada en PostgreSQL:

- 34 alarmas
- 20 eventos
- 10 módulos configurados

También mostró alarmas por módulo, alarmas por severidad, últimas alarmas, eventos del sistema y configuración de módulos.

## Prueba real: marcar alarma como resuelta

Se marcó como resuelta la alarma con ID 34.

Resultado verificado en PostgreSQL:

`alarma: (34, 'ejecutable_en_tmp', 'tmp_monitor', True)`

También se registró un evento real:

`evento_web: ('web', 'alarma_resuelta', 'Alarma 34 marcada como resuelta desde el dashboard')`

## Prueba real: actualizar configuración de módulo

Se actualizó el módulo:

`auth_failures`

Configuración antes:

`('auth_failures', True, 60, 5)`

Configuración después:

`('auth_failures', True, 45, 9)`

También se registró un evento real:

`evento_web: ('web', 'modulo_actualizado', 'Módulo auth_failures actualizado desde el dashboard')`

## Conclusión

La prueba fue exitosa.

El dashboard web no solo muestra información real de PostgreSQL, sino que también modifica datos reales del sistema.
