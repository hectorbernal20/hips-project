# Hardening PostgreSQL basado en CIS

## Entorno

- Sistema operativo: Rocky Linux 9
- Base de datos: PostgreSQL
- Versión detectada: 13.23
- Base de datos del HIPS: hips_db
- Usuario de aplicación: hips_app

## Controles aplicados/verificados

| N.º | Control | Evidencia | Estado |
|---|---|---|---|
| 1 | No usar PGPASSWORD en perfiles | `grep PGPASSWORD ...` no devolvió resultados | Cumple |
| 2 | Logging collector habilitado | `SHOW logging_collector;` devolvió `on` | Cumple |
| 3 | Registro de conexiones habilitado | `SHOW log_connections;` devolvió `on` | Cumple |
| 4 | Registro de desconexiones habilitado | `SHOW log_disconnections;` devolvió `on` | Cumple |
| 5 | Logging de sentencias DDL | `SHOW log_statement;` configurado como `ddl` | Cumple |
| 6 | Prefijo detallado de logs | `SHOW log_line_prefix;` incluye base de datos, usuario, app y cliente | Cumple |
| 7 | Nivel mínimo de logs correcto | `SHOW log_min_messages;` devolvió `warning` | Cumple |
| 8 | Registro de sentencias con error | `SHOW log_min_error_statement;` devolvió `error` | Cumple |
| 9 | Debug parse deshabilitado | `SHOW debug_print_parse;` devolvió `off` | Cumple |
| 10 | Debug rewritten deshabilitado | `SHOW debug_print_rewritten;` devolvió `off` | Cumple |
| 11 | Debug plan deshabilitado | `SHOW debug_print_plan;` devolvió `off` | Cumple |
| 12 | Usuario de aplicación sin privilegios administrativos | `\du` muestra `hips_app` sin atributos elevados | Cumple |

## Privilegios de usuario

El usuario `hips_app` se utiliza para la conexión del sistema HIPS con PostgreSQL. No posee privilegios administrativos como:

- Superuser
- Create role
- Create DB
- Replication
- Bypass RLS

Esto aplica el principio de mínimo privilegio.

## Validación funcional

Se realizó una prueba de inserción desde el módulo de logging del HIPS:

```text
TEST_CIS_POSTGRESQL
```

La alarma fue registrada correctamente en la tabla `alarmas`.

## Conclusión

La base de datos PostgreSQL utilizada por el HIPS cuenta con más de 7 controles de hardening aplicados o verificados, cumpliendo con el requisito del trabajo práctico de aplicar buenas prácticas basadas en CIS.
