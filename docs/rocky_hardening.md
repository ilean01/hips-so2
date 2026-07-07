# Hardening Rocky Linux — HIPS

Sistema operativo: Rocky Linux 9.8  
Proyecto: HIPS  
Usuario de servicio: hips_svc  
Grupo de servicio: hips_group  

Este documento registra los controles de hardening aplicados y verificados en la máquina Rocky Linux utilizada para el sistema HIPS.

---

## 1. SELinux en modo Enforcing

SELinux se mantiene activo en modo Enforcing para aplicar controles obligatorios de acceso.

Verificación:

getenforce

Resultado verificado:

Enforcing

---

## 2. firewalld activo

El firewall del sistema se mantiene activo para controlar el tráfico permitido.

Verificación:

sudo systemctl status firewalld

Resultado verificado:

Active: active (running)

---

## 3. Servicios permitidos por firewall revisados

Se revisó la zona activa de firewalld para identificar los servicios permitidos.

Verificación:

sudo firewall-cmd --list-all

Resultado verificado:

services: cockpit dhcpv6-client ssh

---

## 4. SSH con login root deshabilitado

Se configuró SSH para impedir el acceso directo como root.

Archivo configurado:

/etc/ssh/sshd_config.d/00-hips-hardening.conf

Regla aplicada:

PermitRootLogin no

Verificación:

sudo /usr/sbin/sshd -T | grep permitrootlogin

Resultado verificado:

permitrootlogin no

---

## 5. SSH con banner legal

Se configuró un aviso legal para accesos SSH.

Archivo del banner:

/etc/issue.net

Contenido configurado:

ACCESO RESTRINGIDO - Sistema HIPS. Solo usuarios autorizados. Toda actividad puede ser monitoreada y registrada.

Verificación:

sudo /usr/sbin/sshd -T | grep banner

Resultado verificado:

banner /etc/issue.net

---

## 6. Directorio obligatorio de logs del HIPS

El proyecto exige registrar logs del HIPS en:

/var/log/hips/

Se creó el directorio y los archivos principales:

/var/log/hips/alarmas.log
/var/log/hips/prevencion.log

---

## 7. Permisos restrictivos en logs del HIPS

Los logs del HIPS quedaron protegidos para evitar acceso de usuarios comunes.

Verificación:

sudo ls -ld /var/log/hips
sudo ls -l /var/log/hips

Resultado verificado:

drwxr-x--- hips_svc hips_group /var/log/hips
-rw-r----- hips_svc hips_group alarmas.log
-rw-r----- hips_svc hips_group prevencion.log

---

## 8. Usuario de servicio con mínimo privilegio

Se creó un usuario específico para ejecutar el sistema HIPS sin usar root.

Usuario:

hips_svc

Grupo:

hips_group

Este usuario tiene acceso a los logs del HIPS, pero no debe tener privilegios administrativos generales.

---

## 9. auditd activo

El servicio auditd está activo para registrar eventos de seguridad del sistema.

Verificación:

sudo systemctl status auditd

Resultado verificado:

Active: active (running)

---

## 10. auditd con reglas personalizadas HIPS

Se configuraron reglas de auditoría para vigilar archivos críticos y acciones privilegiadas.

Archivo configurado:

/etc/audit/rules.d/hips.rules

Reglas aplicadas:

-w /etc/passwd -p wa -k hips_identity
-w /etc/shadow -p wa -k hips_identity
-w /etc/sudoers -p wa -k hips_sudoers
-w /etc/sudoers.d/ -p wa -k hips_sudoers
-w /var/log/hips/ -p wa -k hips_logs
-a always,exit -F arch=b64 -S execve -F euid=0 -k hips_privileged_exec
-a always,exit -F arch=b32 -S execve -F euid=0 -k hips_privileged_exec

Verificación:

sudo auditctl -l | grep hips

Resultado verificado:

hips_identity
hips_sudoers
hips_logs
hips_privileged_exec

---

## 11. Servicios innecesarios deshabilitados

Se deshabilitaron servicios no necesarios para un servidor HIPS:

avahi-daemon.service
avahi-daemon.socket
cups.service

Verificación:

systemctl is-active avahi-daemon.service avahi-daemon.socket cups.service

Resultado verificado:

inactive
inactive
inactive

---

## 12. Permisos de archivos críticos verificados

Se verificaron permisos y propietarios de archivos críticos del sistema.

Verificación:

sudo stat -c "%a %U:%G %n" /etc/passwd /etc/shadow /etc/sudoers /var/log/hips /var/log/hips/alarmas.log /var/log/hips/prevencion.log

Resultado verificado:

644 root:root /etc/passwd
0 root:root /etc/shadow
440 root:root /etc/sudoers
750 hips_svc:hips_group /var/log/hips
640 hips_svc:hips_group /var/log/hips/alarmas.log
640 hips_svc:hips_group /var/log/hips/prevencion.log

---

## Resumen de controles

| # | Control | Estado |
|---|---|---|
| 1 | SELinux en Enforcing | Aplicado |
| 2 | firewalld activo | Aplicado |
| 3 | Servicios permitidos por firewall revisados | Aplicado |
| 4 | SSH con PermitRootLogin no | Aplicado |
| 5 | Banner legal SSH | Aplicado |
| 6 | Directorio /var/log/hips creado | Aplicado |
| 7 | Logs HIPS con permisos restrictivos | Aplicado |
| 8 | Usuario hips_svc y grupo hips_group | Aplicado |
| 9 | auditd activo | Aplicado |
| 10 | auditd con reglas personalizadas | Aplicado |
| 11 | Servicios innecesarios deshabilitados | Aplicado |
| 12 | Permisos críticos verificados | Aplicado |
