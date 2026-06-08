# Prueba con Kali - Modulo access_monitor

## Objetivo

Validar que el modulo access_monitor detecta multiples intentos fallidos de acceso SSH hacia el servidor Rocky Linux.

## Entorno

- Maquina de prueba: Kali Linux
- Servidor monitoreado: Rocky Linux
- Servicio probado: SSH
- Modulo HIPS: detection/access_monitor.py
- Archivo analizado: /var/log/secure

## Procedimiento

Desde Kali se generaron intentos fallidos de autenticacion SSH contra Rocky Linux utilizando un usuario inexistente y una clave incorrecta.

Comando de referencia usado desde Kali:

ssh -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    -o NumberOfPasswordPrompts=1 \
    fakeuser@IP_DE_ROCKY

El comando fue repetido varias veces para superar el umbral definido.

En Rocky Linux se verificaron los eventos con:

sudo tail -n 50 /var/log/secure | grep "Failed password"

Luego se ejecuto el detector HIPS:

sudo env PYTHONPATH="$PWD" ./venv/bin/python -m detection.access_monitor --log /var/log/secure --threshold 5 --window 10

## Resultado obtenido

El modulo genero una alarma de tipo:

ACCESO_INVALIDO_REPETIDO

Salida observada:

{'tipo_alarma': 'ACCESO_INVALIDO_REPETIDO', 'ip_origen': '192.168.56.1', 'modulo': 'access_monitor', 'descripcion': '6 intentos fallidos en 10 minutos'}

Tambien se registro en:

/var/log/hips/alarmas.log

Ejemplo de registro:

08/06/2026 11:34:13 :: ACCESO_INVALIDO_REPETIDO :: 192.168.56.1 :: access_monitor :: registrar_alerta :: 6 intentos fallidos en 10 minutos

## Conclusion

La prueba demuestra que el modulo access_monitor puede analizar los logs de SSH en Rocky Linux y detectar multiples intentos fallidos de acceso dentro de una ventana de tiempo definida.
