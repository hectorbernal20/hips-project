# Bloque 2 - Mapa de Trabajo

## 2.1 Módulos del sistema

| # | Módulo / Componente | Responsable | Complejidad | Dependencias | Semana |
|---|---|---|---|---|---|
| i | Integridad de archivos (/etc/passwd, /etc/shadow, binarios) | Hector | Alta | baseline_archivos, logger central | 1 |
| ii | Usuarios conectados (who, last, origen de conexión) | Compañero | Media | logger central, tabla alarmas | 1 |
| iii | Sniffers y modo promiscuo (tcpdump, wireshark, ethereal) | Hector | Media | logger central, prevención | 1 |
| iv | Análisis de logs (/var/log/secure, httpd/access.log, maillog) | Hector | Alta | logger central, PostgreSQL, alertas | 2 |
| v | Cola de correo (mailq, detección de spam masivo) | Compañero | Media | logger central, alertas | 2 |
| vi | Procesos con alto consumo de recursos (CPU / RAM) | Compañero | Media | psutil, logger central | 2 |
| vii | Directorio /tmp (procesos, scripts ejecutables) | Hector | Media | logger central, prevención | 2 |
| viii | Ataques DDoS (log DNS provisto por el profesor) | Compañero | Alta | log DNS, PostgreSQL, alertas | 3 |
| ix | Archivos cron sospechosos (/etc/crontab, /var/spool/cron) | Hector | Media | logger central, prevención | 3 |
| x | Intentos de acceso inválidos (brute force, credential stuffing) | Hector | Alta | /var/log/secure, prevención, alertas | 3 |

## Infraestructura

| # | Módulo / Componente | Responsable | Complejidad | Dependencias | Semana |
|---|---|---|---|---|---|
| - | Módulo de Prevención | Hector y Compañero | Alta | todos los módulos de detección | 3 |
| - | Interfaz web + dashboard | Compañero | Alta | PostgreSQL, tabla alarmas | 4 |
| - | Sistema de alertas por email + dashboard | Hector | Media | web, alarmas, logger central | 4 |
| - | Logger central (/var/log/hips/) | Hector | Media | todos los módulos | 1 |
| - | PostgreSQL + 7 controles CIS | Hector | Alta | base de datos, hardening | 1 |
| - | Carpeta encriptada de configuración | Compañero | Media | config, variables de entorno | 2 |
| - | Rocky Linux + 10 controles de hardening | Hector | Alta | sistema operativo Rocky Linux | 1 |
| - | Suite de pruebas automatizadas | Hector y Compañero | Alta | pytest, módulos de detección | 4 |
| - | Manual de uso + manual de instalación | Hector y Compañero | Media | sistema terminado | 4 |

## Criterio de complejidad

- Alta: requiere más de 2 días.
- Media: requiere entre 1 y 2 días.
- Baja: requiere menos de 1 día.

## Justificación general

Se asignan como alta complejidad los módulos que requieren mayor análisis, múltiples fuentes de datos o integración con prevención, como integridad de archivos, análisis de logs, DDoS, accesos inválidos, PostgreSQL y hardening del sistema operativo.

Los módulos de complejidad media tienen una fuente de datos más concreta o una lógica más acotada, como usuarios conectados, sniffers, cola de correo, procesos, directorio /tmp y archivos cron.

La planificación se distribuye en cuatro semanas: primero infraestructura base, luego módulos intermedios, después prevención y módulos complejos, y finalmente dashboard, pruebas y documentación.
