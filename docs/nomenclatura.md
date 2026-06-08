# Bloque 3 - Protocolo de Nomenclatura

## 3.1 Nombre del proyecto

| Item | Decision |
|---|---|
| Nombre del proyecto | hips_project |
| Prefijo del sistema | HIPS_ para variables de entorno y hips. para logs |
| Repositorio | hips-project |

## 3.2 Archivos y carpetas

| Item | Convencion | Ejemplo |
|---|---|---|
| Modulos Python | snake_case | sniffer_detect.py |
| Carpetas | snake_case | detection/, prevention/, alerts/ |
| Archivos de configuracion | snake_case o punto inicial | .env, hips_config.py |
| Templates HTML | kebab-case | dashboard-alerts.html |
| Archivos de prueba | test_nombre_modulo.py | test_sniffer_detect.py |

## 3.3 Codigo Python

| Item | Convencion | Ejemplo |
|---|---|---|
| Funciones | snake_case | detect_sniffer() |
| Clases | PascalCase | SnifferDetector |
| Constantes | UPPER_SNAKE_CASE | MAX_FAILED_ATTEMPTS |
| Variables | snake_case | ip_origen |
| Variables de entorno | UPPER_SNAKE_CASE con prefijo HIPS_ | HIPS_DB_PASSWORD |

## 3.4 Base de datos PostgreSQL

| Item | Convencion | Ejemplo |
|---|---|---|
| Tablas | snake_case en plural | alarmas |
| Columnas | snake_case | ip_origen |
| Claves primarias | id | id |
| Claves foraneas | tabla_id | alarma_id |
| Indices | idx_tabla_columna | idx_alarmas_timestamp |
| Usuario de aplicacion | nombre restrictivo sin superusuario | hips_app |

## 3.5 Git - Ramas y commits

| Item | Convencion |
|---|---|
| Rama principal | main |
| Ramas de modulos | feat/modulo-nombre |
| Ramas de correccion | fix/descripcion |
| Ramas de documentacion | docs/descripcion |
| Formato de commit | tipo(modulo): descripcion |
| Tipos de commit | feat, fix, docs, test, refactor, chore |
| Frecuencia minima | Al terminar cada documento, funcion o modulo probado |

Ejemplos:

- feat(sniffer): detectar modo promiscuo
- docs(stack): agregar controles de hardening
- test(access): agregar prueba de accesos invalidos
- fix(logger): corregir formato de logs

## 3.6 Tipos de alarma en logs

Formato general:

DD/MM/YYYY HH:MM:SS :: TIPO_ALARMA :: IP_ORIGEN :: MODULO :: DESCRIPCION

| Modulo | Tipo de alarma |
|---|---|
| Integridad de archivos | MODIFICACION_ARCHIVO |
| Usuarios conectados | USUARIO_SOSPECHOSO |
| Sniffers | SNIFFER_DETECTADO |
| Analisis de logs | FAILED_LOGIN_MULTIPLE |
| Analisis de logs HTTP | SCANNER_HTTP |
| Cola de correo | MAIL_QUEUE_ALTA |
| Procesos con alto consumo | PROCESO_ALTO_CONSUMO |
| Directorio tmp | ARCHIVO_TMP_SOSPECHOSO |
| Ataques DDoS | DDOS_DETECTADO |
| Cron sospechoso | CRON_SOSPECHOSO |
| Accesos invalidos | ACCESO_INVALIDO_REPETIDO |
| Credential stuffing | CREDENTIAL_STUFFING |

## 3.7 Reglas generales

1. No guardar contrasenas reales en el repositorio.
2. Usar .env.example como plantilla.
3. Mantener un archivo Python por modulo.
4. Registrar todas las alarmas con el logger central.
5. Toda accion de prevencion debe quedar registrada.
6. Todo modulo debe tener al menos una prueba automatizada.
