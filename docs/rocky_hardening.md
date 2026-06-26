# Hardening Rocky Linux

## Entorno

- Sistema operativo: Rocky Linux 9
- Host utilizado para el HIPS
- Usuario operativo: hector
- Servicio principal protegido: HIPS + PostgreSQL

## Controles aplicados/verificados

| N.º | Control | Evidencia | Estado |
|---|---|---|---|
| 1 | Uso de Rocky Linux 9 como sistema base | `/etc/os-release` identifica Rocky Linux | Cumple |
| 2 | SELinux disponible en el sistema | `getenforce` permite verificar el estado de SELinux | Verificado |
| 3 | Firewall activo mediante firewalld | `systemctl is-active firewalld` y `firewall-cmd --list-all` | Cumple |
| 4 | Puerto del dashboard controlado por firewall | Puerto `5000/tcp` habilitado para acceso web controlado | Cumple |
| 5 | SSH habilitado para administración remota | Servicio SSH usado para acceso desde PuTTY | Cumple |
| 6 | PostgreSQL ejecutándose como servicio administrado | `postgresql.service` figura `enabled` y `active` | Cumple |
| 7 | Logs del HIPS centralizados | Logs ubicados en `/var/log/hips/` | Cumple |
| 8 | Permisos revisados en archivos sensibles | `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow` revisados | Cumple |
| 9 | Revisión de usuarios con UID 0 | Se verifica que solo usuarios autorizados tengan UID 0 | Cumple |
| 10 | Revisión de puertos en escucha | `ss -tulpen` permite validar servicios expuestos | Cumple |
| 11 | Sin uso de root como usuario de trabajo | Desarrollo realizado con usuario `hector` y uso de `sudo` | Cumple |
| 12 | Actualizaciones del sistema verificadas | `dnf check-update` muestra paquetes disponibles para revisión | Verificado |

## Evidencia generada

La evidencia técnica fue exportada al archivo:

```text
docs/rocky_hardening_evidence.txt
```

Este archivo contiene la salida de comandos de verificación sobre:

- Sistema operativo
- SELinux
- Firewalld
- SSH
- Auditd
- Chronyd
- Rsyslog
- Permisos de archivos sensibles
- Usuarios con UID 0
- Puertos en escucha
- Actualizaciones disponibles
- Estado de PostgreSQL

## Observación sobre actualizaciones

El comando `dnf check-update` mostró paquetes disponibles. Esto no impide la entrega del TP, pero debe documentarse como una revisión realizada. En un entorno productivo se recomienda aplicar actualizaciones controladas con:

```text
sudo dnf update
```

En este entorno de práctica se deja documentado para evitar cambios mayores no planificados antes de la entrega.

## Conclusión

La máquina Rocky Linux utilizada para el HIPS cuenta con al menos 10 controles de hardening aplicados o verificados, cumpliendo con el requisito del trabajo práctico.
