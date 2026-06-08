# HIPS Project

Sistema HIPS desarrollado para la materia Sistemas Operativos.

## Stack tecnológico

- Sistema operativo objetivo: Rocky Linux 9.6 Minimal
- Lenguaje principal: Python 3.x
- Framework web: Flask
- Base de datos: PostgreSQL
- Pruebas automatizadas: pytest

## Módulos de detección

1. Integridad de archivos
2. Usuarios conectados
3. Sniffers y modo promiscuo
4. Análisis de logs
5. Cola de correo
6. Procesos con alto consumo
7. Directorio /tmp
8. Ataques DDoS
9. Cron sospechoso
10. Intentos de acceso inválidos

## Estructura del proyecto

- detection/: módulos de detección
- prevention/: acciones de prevención
- alerts/: logger y envío de correos
- web/: dashboard web
- db/: modelos y migraciones
- config/: configuración protegida
- tests/: pruebas automatizadas
- docs/: documentación del proyecto
