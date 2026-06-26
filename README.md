# HIPS Project

Sistema HIPS desarrollado para Rocky Linux 9.

El proyecto implementa detección, prevención, registro de eventos, persistencia en PostgreSQL y dashboard web para monitoreo.

## Componentes principales

- Módulos de detección en `detection/`
- Módulos de prevención en `prevention/`
- Logging centralizado en `alerts/`
- Persistencia en PostgreSQL mediante `db/`
- Dashboard web Flask en `web/`
- Evidencias y documentación en `docs/`

## Requisitos principales

- Rocky Linux 9
- Python 3
- PostgreSQL
- Flask
- psycopg2
- python-dotenv
- flask-login

## Configuración

El sistema utiliza variables de entorno cargadas desde `.env`.

El archivo `.env` no debe subirse al repositorio porque contiene credenciales.

Se incluye `.env.example` como plantilla segura.

## Ejecución del entorno

Activar el entorno virtual:

    cd ~/hips-project
    source venv/bin/activate

## Dashboard web

Ejecutar dashboard:

    cd ~/hips-project
    source venv/bin/activate
    python web/app.py

Acceso desde navegador:

    http://IP_DEL_SERVIDOR:5000

El usuario y contraseña se configuran desde `.env`.

## Logs principales

El sistema registra eventos en:

    /var/log/hips/alarmas.log
    /var/log/hips/prevencion.log
    /var/log/hips/emails.log

## Base de datos

Base de datos utilizada:

    hips_db

Tablas principales:

- alarmas
- acciones_prevencion
- eventos_sistema

## Módulos de detección

| Módulo | Objetivo |
|---|---|
| access_monitor.py | Detectar intentos inválidos de acceso |
| file_integrity.py | Detectar modificación de archivos críticos |
| users_monitor.py | Detectar usuarios u orígenes sospechosos |
| sniffer_detect.py | Detectar sniffers y modo promiscuo |
| log_analyzer.py | Analizar logs de autenticación, HTTP y correo |
| process_monitor.py | Detectar procesos de alto consumo |
| tmp_monitor.py | Detectar archivos y procesos sospechosos en /tmp |
| cron_monitor.py | Detectar tareas cron sospechosas |
| ddos_detect.py | Detectar patrones de DDoS DNS |
| mail_queue.py | Detectar anomalías en cola de correo |

## Módulos de prevención

| Módulo | Función |
|---|---|
| firewall.py | Bloqueo de IPs |
| process_kill.py | Finalización de procesos sospechosos |
| quarantine.py | Cuarentena de archivos |
| service_mgmt.py | Gestión defensiva de servicios |
| sniffer_actions.py | Acciones contra sniffers |
| user_actions.py | Acciones sobre usuarios |
| cron_actions.py | Acciones sobre tareas cron |

## Hardening

El proyecto documenta controles de hardening en:

    docs/postgresql_cis_hardening.md
    docs/rocky_hardening.md

## Pruebas finales

Las pruebas integrales están documentadas en:

    docs/test_evidence/phase12_test_summary.md
    docs/test_evidence/phase12_full_test_output.txt

## Estado de entrega

El sistema cumple con:

- Detección de eventos sospechosos
- Acciones preventivas
- Registro de alarmas
- Registro de prevenciones
- Simulación de envío de emails
- Persistencia en PostgreSQL
- Dashboard protegido con login
- Hardening PostgreSQL basado en CIS
- Hardening Rocky Linux
- Evidencias de pruebas finales
