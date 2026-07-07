# Taller de Kickoff de Desarrollo — HIPS

Materia: Sistemas Operativos  
Proyecto: HIPS sobre Rocky Linux 9.8  
Repositorio: hips-so2  
Integrantes: Ileana Sanabria y compañero/a  
Fecha: 7 de julio de 2026  

---

## 1. Stack Tecnológico y Hardening

### 1.1 Decisiones del stack

| Componente | Elección + Justificación |
|---|---|
| Lenguaje principal | Python 3.x. Se elige porque permite leer archivos del sistema, ejecutar comandos de Linux, procesar logs, conectarse a PostgreSQL y automatizar pruebas con pytest. Bash se usará solamente como apoyo para comandos simples. |
| Web framework | Flask. Se elige porque es liviano, fácil de configurar en Rocky Linux y suficiente para crear un dashboard web de alarmas, módulos y configuración. |

---

## 1.2 Hardening del Sistema Operativo — Rocky Linux

| # | Área / Control | Descripción | Comando de verificación o implementación |
|---|---|---|---|
| 1 | SELinux en enforcing | Mantener SELinux activo para controlar accesos no autorizados a archivos, procesos y servicios. | `getenforce` |
| 2 | Firewalld activo | Activar firewall del sistema y permitir solo servicios necesarios. | `sudo systemctl status firewalld` / `sudo firewall-cmd --list-all` |
| 3 | SSH sin acceso root | Evitar que el usuario root inicie sesión por SSH directamente. | `sudo grep PermitRootLogin /etc/ssh/sshd_config` |
| 4 | SSH con autenticación segura | Revisar la política de autenticación SSH para reducir ataques de fuerza bruta. | `sudo grep PasswordAuthentication /etc/ssh/sshd_config` |
| 5 | Usuarios con mínimos privilegios | Crear usuarios de aplicación sin permisos de administrador. | `id hips_app` |
| 6 | Auditd activo | Registrar eventos importantes del sistema para auditoría. | `sudo systemctl status auditd` |
| 7 | Banner de login | Mostrar advertencia antes de iniciar sesión. | `cat /etc/issue` |
| 8 | Permisos seguros en archivos críticos | Verificar permisos de `/etc/passwd` y `/etc/shadow`. | `ls -l /etc/passwd /etc/shadow` |
| 9 | Actualizaciones de seguridad | Mantener Rocky Linux actualizado para corregir vulnerabilidades. | `sudo dnf update --security --assumeno` |
| 10 | Control del directorio `/tmp` | Detectar scripts o archivos ejecutables sospechosos en `/tmp`. | `find /tmp -type f -perm /111` |

---

## Evidencia inicial realizada

- PostgreSQL Server fue instalado.
- PostgreSQL fue inicializado con `sudo postgresql-setup --initdb`.
- El servicio PostgreSQL quedó activo con `sudo systemctl enable --now postgresql`.
- Se creó el usuario `hips_app`.
- Se creó la base de datos `hips_db`.
- Se verificó que `hips_app` no es superusuario.
- Se creó el repositorio GitHub `hips-so2`.
- Se configuró SSH para subir commits desde Rocky Linux.
- Se subió el primer commit con la estructura inicial del proyecto.
