# Bloque 4 - Analisis de Requerimientos

## Modulos elegidos

Se eligen los siguientes tres modulos iniciales:

1. Modulo iii: Sniffers y modo promiscuo.
2. Modulo iv: Analisis de logs.
3. Modulo x: Intentos de acceso invalidos.

Estos modulos se seleccionan porque permiten cubrir deteccion de procesos sospechosos, analisis de eventos del sistema y posibles ataques de fuerza bruta.

---

# Modulo iii - Sniffers y modo promiscuo

| Campo | Completar |
|---|---|
| Nombre del modulo | Modulo iii: Sniffers y modo promiscuo |
| Objetivo concreto | Detectar herramientas de captura de trafico o interfaces de red en modo promiscuo. |
| Fuentes de datos | Comandos `ip link`, `ps aux`, `ss -tulpn`; procesos como tcpdump, wireshark, tshark o dumpcap. |
| Condicion de alarma | Se dispara si una interfaz aparece en modo promiscuo o si se detecta un proceso de captura de trafico activo. |
| Comportamiento normal | Administradores ejecutando diagnosticos de red autorizados por un tiempo limitado. |
| Comportamiento anomalo | Un usuario no autorizado ejecuta tcpdump, wireshark o activa modo promiscuo en una interfaz. |
| Parametros configurables | Lista de procesos permitidos, tiempo maximo permitido, interfaces ignoradas. |
| Logica de deteccion | 1. Revisar interfaces con `ip link`. 2. Buscar flag PROMISC. 3. Buscar procesos sospechosos. 4. Generar alarma si corresponde. |
| Accion de prevencion | Registrar evento, notificar al administrador y opcionalmente finalizar el proceso sospechoso. |
| Tipo de alarma en log | SNIFFER_DETECTADO |
| Contenido del email al admin | Asunto: [HIPS ALERTA] Sniffer detectado. Cuerpo: Se detecto interfaz en modo promiscuo o proceso de captura activo. |
| Visibilidad en dashboard | timestamp, tipo, ip_origen, modulo, accion_tomada |
| Casos borde / excepciones | Uso legitimo de tcpdump por administradores, herramientas de monitoreo autorizadas. |
| Test automatizable | Simular un proceso llamado tcpdump o activar una condicion controlada para verificar que se genere la alarma. |

---

# Modulo iv - Analisis de logs

| Campo | Completar |
|---|---|
| Nombre del modulo | Modulo iv: Analisis de logs |
| Objetivo concreto | Detectar eventos sospechosos a partir de logs del sistema y servicios. |
| Fuentes de datos | `/var/log/secure`, `/var/log/messages`, `httpd/access.log`, `maillog` si existen. |
| Condicion de alarma | Se dispara si aparecen multiples errores de autenticacion, patrones de escaneo HTTP o eventos repetidos desde una misma IP. |
| Comportamiento normal | Algunos errores aislados de login o peticiones web normales. |
| Comportamiento anomalo | Muchos intentos fallidos, rutas web repetidas sospechosas o errores repetitivos desde una misma IP. |
| Parametros configurables | Cantidad maxima de eventos, ventana de tiempo, rutas HTTP sospechosas, IPs ignoradas. |
| Logica de deteccion | 1. Leer logs configurados. 2. Extraer timestamp, evento e IP. 3. Agrupar por IP y tipo de evento. 4. Comparar con umbrales. 5. Generar alarma. |
| Accion de prevencion | Registrar alarma, enviar email y opcionalmente bloquear IP mediante firewall. |
| Tipo de alarma en log | FAILED_LOGIN_MULTIPLE o SCANNER_HTTP |
| Contenido del email al admin | Asunto: [HIPS ALERTA] Evento sospechoso en logs. Cuerpo: Se detectaron multiples eventos sospechosos desde una misma IP. |
| Visibilidad en dashboard | timestamp, tipo, ip_origen, modulo, accion_tomada |
| Casos borde / excepciones | Usuarios que olvidan su clave, bots normales, escaneos internos autorizados. |
| Test automatizable | Crear un archivo de log falso con eventos repetidos y verificar que el modulo genere la alarma esperada. |

---

# Modulo x - Intentos de acceso invalidos

| Campo | Completar |
|---|---|
| Nombre del modulo | Modulo x: Intentos de acceso invalidos |
| Objetivo concreto | Detectar ataques de fuerza bruta o credential stuffing contra servicios de autenticacion. |
| Fuentes de datos | Principalmente `/var/log/secure` y registros de SSH. |
| Condicion de alarma | Se dispara si una IP genera mas de 5 intentos fallidos en una ventana de 10 minutos. |
| Comportamiento normal | Uno o dos errores de login de un usuario legitimo. |
| Comportamiento anomalo | Muchos intentos fallidos desde una misma IP o intentos con multiples usuarios distintos. |
| Parametros configurables | Cantidad maxima de intentos, ventana de tiempo, lista blanca de IPs, duracion del bloqueo. |
| Logica de deteccion | 1. Leer `/var/log/secure`. 2. Buscar eventos de autenticacion fallida. 3. Extraer IP origen. 4. Contar intentos por IP. 5. Generar alarma si supera el umbral. |
| Accion de prevencion | Registrar alarma, enviar email y bloquear temporalmente la IP con firewalld. |
| Tipo de alarma en log | ACCESO_INVALIDO_REPETIDO o CREDENTIAL_STUFFING |
| Contenido del email al admin | Asunto: [HIPS ALERTA] Intentos invalidos repetidos. Cuerpo: Se detectaron mas de 5 intentos fallidos desde una IP en 10 minutos. |
| Visibilidad en dashboard | timestamp, tipo, ip_origen, modulo, accion_tomada |
| Casos borde / excepciones | Usuario legitimo con clave incorrecta, pruebas internas, scripts de administracion mal configurados. |
| Test automatizable | Usar un log de prueba con mas de 5 intentos fallidos desde la misma IP y verificar que se genere la alarma. |

---

# Decision de arranque

El primer modulo a implementar sera `access_monitor.py`, porque permite probar el flujo completo del sistema:

1. Lectura de logs.
2. Deteccion por umbral.
3. Registro de alarma.
4. Accion de prevencion.
5. Prueba automatizada.
