# Bloque 1 - Stack Tecnológico y Hardening

## 1.1 Decisiones del stack

| Componente | Elección | Justificación |
|---|---|---|
| Lenguaje principal | Python 3.x | Permite automatizar tareas del sistema, leer logs, ejecutar comandos, analizar procesos y crear pruebas de forma simple. |
| Web framework | Flask | Es liviano, suficiente para un dashboard básico y más simple de implementar que Django para este alcance. |
| Base de datos | PostgreSQL | Es requerida por el proyecto y permite aplicar controles de seguridad basados en CIS. |
| Sistema operativo | Rocky Linux 9.6 Minimal | Es una distribución estable orientada a servidores y compatible con prácticas de hardening tipo RHEL. |
| Pruebas | pytest | Permite automatizar pruebas de los módulos de detección. |

## 1.2 Hardening del Sistema Operativo - Rocky Linux

| # | Área / Control | Descripción | Verificación |
|---|---|---|---|
| 1 | SELinux enforcing | Mantener SELinux en modo enforcing para restringir acciones no autorizadas. | `getenforce` |
| 2 | firewalld activo | Activar firewall del sistema y permitir solo servicios necesarios. | `systemctl status firewalld` |
| 3 | SSH activo controlado | Permitir administración remota por SSH. | `systemctl status sshd` |
| 4 | Bloquear root por SSH | Evitar acceso directo como root por SSH. | `sudo grep PermitRootLogin /etc/ssh/sshd_config` |
| 5 | Usuarios con privilegios mínimos | Usar usuario normal con sudo solo cuando sea necesario. | `groups hector` |
| 6 | auditd activo | Registrar eventos relevantes del sistema. | `systemctl status auditd` |
| 7 | Banner de login | Mostrar advertencia legal antes del acceso. | `cat /etc/issue` |
| 8 | Permisos en /etc/passwd | Verificar permisos seguros en archivo de usuarios. | `ls -l /etc/passwd` |
| 9 | Permisos en /etc/shadow | Verificar que solo root pueda leer hashes de contraseñas. | `ls -l /etc/shadow` |
| 10 | Servicios innecesarios | Revisar servicios activos y deshabilitar los no requeridos. | `systemctl list-unit-files --type=service --state=enabled` |

## 1.3 Hardening de PostgreSQL - CIS

| # | Control / Área | Descripción | Verificación |
|---|---|---|---|
| 1 | Usuario sin superusuario | La aplicación usa `hips_app`, sin permisos de superusuario. | `\du` |
| 2 | Base de datos separada | La aplicación usa una base propia llamada `hips_db`. | `\l` |
| 3 | Contraseñas fuera del código | Las credenciales se cargan desde `.env`, no desde código fuente. | `cat .env.example` |
| 4 | password_encryption | Usar cifrado seguro para contraseñas. | `SHOW password_encryption;` |
| 5 | listen_addresses restringido | Evitar exposición innecesaria del servidor PostgreSQL. | `SHOW listen_addresses;` |
| 6 | log_connections | Registrar conexiones entrantes. | `SHOW log_connections;` |
| 7 | log_disconnections | Registrar desconexiones. | `SHOW log_disconnections;` |

## 1.4 Esquema inicial de base de datos

| Tabla | Columnas mínimas | Propósito |
|---|---|---|
| alarmas | id, timestamp, tipo_alarma, ip_origen, modulo, resuelta | Registro de alarmas detectadas |
| acciones_prevencion | id, alarma_id, accion, timestamp, resultado | Log de acciones tomadas |
| usuarios_web | id, username, password_hash, rol, ultimo_login | Acceso al dashboard |
| configuracion_modulos | id, modulo, parametro, valor, activo | Parámetros configurables de cada módulo |
| eventos_sistema | id, timestamp, evento, origen, detalle | Registro general de eventos relevantes |
| baseline_archivos | id, ruta_archivo, hash, ultima_revision | Control de integridad de archivos |
