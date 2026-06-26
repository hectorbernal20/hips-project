# Checklist final de entrega - HIPS

## 1. Requisitos principales del TP

| Requisito | Estado | Evidencia |
|---|---|---|
| Sistema HIPS sobre Rocky Linux | Cumple | Proyecto ejecutado en Rocky Linux 9 |
| Detección de eventos sospechosos | Cumple | Módulos en detection/ |
| Prevención de incidentes | Cumple | Módulos en prevention/ |
| Al menos 10 controles de hardening Rocky Linux | Cumple | docs/rocky_hardening.md |
| Hardening PostgreSQL basado en CIS | Cumple | docs/postgresql_cis_hardening.md |
| Al menos 7 buenas prácticas CIS PostgreSQL | Cumple | docs/postgresql_cis_hardening.md |
| Dashboard web con login | Cumple | web/app.py y web/templates/ |
| Configuración de módulos en dashboard | Cumple | web/templates/config.html |
| Revisión de alertas en dashboard | Cumple | web/templates/dashboard.html |
| Logs en /var/log/hips/ | Cumple | alarmas.log, prevencion.log, emails.log |
| Formato de alarma requerido | Cumple | timestamp :: Tipo de Alarma :: IP origen |
| Emails generados por alarma/prevención | Cumple | /var/log/hips/emails.log |
| Persistencia en PostgreSQL | Cumple | tablas alarmas, acciones_prevencion, eventos_sistema |
| Pruebas automatizadas/simuladas | Cumple | docs/test_evidence/ |
| Sin contraseñas en código fuente | Cumple | uso de .env y .env.example |

## 2. Módulos de detección implementados

| Módulo | Estado |
|---|---|
| access_monitor.py | Implementado |
| file_integrity.py | Implementado |
| users_monitor.py | Implementado |
| sniffer_detect.py | Implementado |
| log_analyzer.py | Implementado |
| process_monitor.py | Implementado |
| tmp_monitor.py | Implementado |
| cron_monitor.py | Implementado |
| ddos_detect.py | Implementado |
| mail_queue.py | Implementado |

## 3. Módulos de prevención implementados

| Módulo | Estado |
|---|---|
| firewall.py | Implementado |
| process_kill.py | Implementado |
| quarantine.py | Implementado |
| service_mgmt.py | Implementado |
| sniffer_actions.py | Implementado |
| user_actions.py | Implementado |
| cron_actions.py | Implementado |

## 4. Archivos importantes del proyecto

| Archivo o carpeta | Descripción |
|---|---|
| README.md | Descripción general del proyecto |
| .env.example | Plantilla segura de variables de entorno |
| database/schema.sql | Esquema de base de datos |
| alerts/logger.py | Registro de alarmas y prevenciones |
| alerts/mailer.py | Simulación de envío de emails |
| db/ | Conexión y repositorio PostgreSQL |
| detection/ | Módulos de detección |
| prevention/ | Módulos de prevención |
| web/ | Dashboard Flask |
| docs/manual_usuario.md | Manual de uso |
| docs/postgresql_cis_hardening.md | Hardening PostgreSQL |
| docs/rocky_hardening.md | Hardening Rocky Linux |
| docs/test_evidence/phase12_test_summary.md | Resumen de pruebas finales |
| docs/test_evidence/phase12_full_test_output.txt | Evidencia completa de pruebas |

## 5. Comandos útiles para defensa

Activar entorno:

    cd ~/hips-project
    source venv/bin/activate

Ejecutar dashboard:

    python web/app.py

Ver alarmas:

    sudo tail -n 50 /var/log/hips/alarmas.log

Ver prevenciones:

    sudo tail -n 50 /var/log/hips/prevencion.log

Ver emails generados:

    sudo tail -n 50 /var/log/hips/emails.log

Consultar alarmas en PostgreSQL:

    sudo -u postgres psql -d hips_db -c "SELECT id, timestamp, tipo_alarma, ip_origen, modulo FROM alarmas ORDER BY id DESC LIMIT 20;"

Consultar prevenciones en PostgreSQL:

    sudo -u postgres psql -d hips_db -c "SELECT id, timestamp, tipo_alarma, ip_origen, accion, resultado FROM acciones_prevencion ORDER BY id DESC LIMIT 20;"

Ejecutar pruebas finales:

    sudo docs/test_evidence/run_phase12_tests.sh > docs/test_evidence/phase12_full_test_output.txt 2>&1

## 6. Estado final

El proyecto HIPS queda documentado, probado y con evidencia suficiente para la entrega.
