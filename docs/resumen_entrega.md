# Resumen de Entrega - HIPS

## Proyecto

Repositorio: https://github.com/hectorbernal20/hips-project

Sistema HIPS desarrollado sobre Rocky Linux, con módulos de detección, prevención, PostgreSQL, hardening y pruebas automatizadas.

## Entregables del taller

| Entregable | Estado | Archivo |
|---|---|---|
| Stack tecnológico | Completo | docs/stack_hardening.md |
| Hardening Rocky Linux | Completo | docs/stack_hardening.md / docs/hardening_verificacion.md |
| Hardening PostgreSQL | Completo | docs/stack_hardening.md / docs/hardening_verificacion.md |
| Esquema inicial de BD | Completo | db/migrations/001_initial_schema.sql |
| Mapa de trabajo | Completo | docs/mapa_trabajo.md |
| Protocolo de nomenclatura | Completo | docs/nomenclatura.md |
| Análisis de 3 módulos | Completo | docs/requerimientos_modulos.md |
| Repositorio Git | Completo | GitHub |
| Prueba con Kali | Completo | docs/kali_prueba_access_monitor.md |

## Módulos implementados

### Detección

- detection/access_monitor.py

Detecta múltiples intentos fallidos de autenticación SSH desde una misma IP dentro de una ventana de tiempo.

### Prevención

- prevention/firewall.py

Define una acción preventiva segura mediante firewall. Por seguridad, se implementó con modo dry-run para evitar bloquear accidentalmente la conexión del entorno de prueba.

### Alertas

- alerts/logger.py

Registra alarmas en:

/var/log/hips/alarmas.log

## Pruebas automatizadas

Para ejecutar las pruebas:

pytest

Resultado esperado:

3 passed

## Prueba práctica con Kali

Desde Kali se generaron intentos fallidos de SSH contra Rocky Linux. Luego, en Rocky se ejecutó:

sudo env PYTHONPATH="$PWD" ./venv/bin/python -m detection.access_monitor --log /var/log/secure --threshold 5 --window 10 --prevent

Resultado obtenido:

ACCESO_INVALIDO_REPETIDO

## Verificaciones importantes

### Rocky Linux

getenforce
sudo sshd -T | grep -E "permitrootlogin|maxauthtries|logingracetime"
ls -l /etc/passwd /etc/shadow
ls -ld /var/log/hips

### PostgreSQL

sudo -u postgres psql -c "SHOW password_encryption;"
sudo -u postgres psql -c "SHOW listen_addresses;"
sudo -u postgres psql -c "SHOW log_connections;"
sudo -u postgres psql -c "SHOW log_disconnections;"

### Base de datos

PGPASSWORD='HipsApp_123456' psql -h 127.0.0.1 -U hips_app -d hips_db -c "\dt"

## Conclusión

El proyecto cumple con el kickoff del HIPS: se definió el stack, se configuró Rocky Linux, se aplicaron controles de hardening, se creó PostgreSQL con esquema inicial, se documentaron módulos y se implementó una prueba funcional usando Kali como máquina de prueba.
