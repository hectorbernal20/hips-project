# Fase 12 - Pruebas finales del HIPS

## Objetivo

Validar el funcionamiento integral de los módulos de detección, prevención, logging, notificación y persistencia en PostgreSQL del sistema HIPS.

## Módulos probados

| Módulo | Resultado esperado |
|---|---|
| access_monitor.py | Detectar intentos inválidos de acceso SSH |
| file_integrity.py | Detectar modificación de archivo monitoreado |
| users_monitor.py | Detectar usuario u origen no autorizado |
| sniffer_detect.py | Detectar procesos sniffers y modo promiscuo |
| log_analyzer.py | Detectar abuso de autenticación, scanner HTTP y envío masivo |
| process_monitor.py | Detectar procesos con alto consumo |
| tmp_monitor.py | Detectar archivos/procesos sospechosos en `/tmp` |
| cron_monitor.py | Detectar tareas cron sospechosas |
| ddos_detect.py | Detectar patrón de ataque DDoS DNS |
| mail_queue.py | Detectar cola de correo anómala |

## Evidencia generada

La salida completa de las pruebas se guardó en:

```text
docs/test_evidence/phase12_full_test_output.txt
Validaciones realizadas
Compilación de sintaxis Python con py_compile.
Ejecución de módulos de detección con archivos simulados.
Ejecución de acciones preventivas en modo seguro.
Registro de alarmas en /var/log/hips/alarmas.log.
Registro de prevenciones en /var/log/hips/prevencion.log.
Registro de emails generados en /var/log/hips/emails.log.
Inserción de alarmas y prevenciones en PostgreSQL.
Consulta final de tablas alarmas y acciones_prevencion.
Conclusión

Las pruebas finales validan que el HIPS detecta eventos sospechosos, ejecuta acciones preventivas, registra evidencia en archivos de log y persiste los eventos relevantes en PostgreSQL.
