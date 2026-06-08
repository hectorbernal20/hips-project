# Verificacion de Hardening - Rocky Linux y PostgreSQL

## Rocky Linux - Controles aplicados

| # | Control | Comando de verificacion | Resultado esperado |
|---|---|---|---|
| 1 | SELinux enforcing | getenforce | Enforcing |
| 2 | firewalld activo | systemctl status firewalld | active running |
| 3 | SSH activo | systemctl status sshd | active running |
| 4 | Root deshabilitado por SSH | sudo sshd -T \| grep permitrootlogin | permitrootlogin no |
| 5 | MaxAuthTries limitado | sudo sshd -T \| grep maxauthtries | maxauthtries 3 |
| 6 | LoginGraceTime limitado | sudo sshd -T \| grep logingracetime | logingracetime 60 |
| 7 | Banner de login | cat /etc/issue.net | Acceso restringido |
| 8 | auditd activo | systemctl status auditd | active running |
| 9 | Permisos seguros en archivos criticos | ls -l /etc/passwd /etc/shadow | permisos restringidos |
| 10 | Directorio de logs HIPS protegido | ls -ld /var/log/hips | acceso controlado |

## PostgreSQL - Controles aplicados

| # | Control | Comando de verificacion | Resultado esperado |
|---|---|---|---|
| 1 | Usuario de aplicacion sin superusuario | sudo -u postgres psql -c "\du" | hips_app sin superusuario |
| 2 | Base de datos separada | sudo -u postgres psql -l | hips_db existente |
| 3 | Autenticacion SCRAM | sudo grep scram-sha-256 /var/lib/pgsql/data/pg_hba.conf | scram-sha-256 |
| 4 | password_encryption seguro | sudo -u postgres psql -c "SHOW password_encryption;" | scram-sha-256 |
| 5 | listen_addresses restringido | sudo -u postgres psql -c "SHOW listen_addresses;" | localhost |
| 6 | log_connections activo | sudo -u postgres psql -c "SHOW log_connections;" | on |
| 7 | log_disconnections activo | sudo -u postgres psql -c "SHOW log_disconnections;" | on |

## Observacion

Los controles fueron aplicados en Rocky Linux y PostgreSQL con comandos verificables. Esto permite demostrar el cumplimiento del hardening solicitado para el sistema HIPS.
