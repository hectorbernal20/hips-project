import json
import sys

from db.connection import get_connection


def _json_or_none(raw_data):
    if raw_data is None:
        return None

    return json.dumps(raw_data, ensure_ascii=False)


def _safe_execute(query, params):
    connection = None

    try:
        connection = get_connection()

        if connection is None:
            return False

        with connection:
            with connection.cursor() as cursor:
                cursor.execute(query, params)

        return True

    except Exception as error:
        print(f"[HIPS DB WARNING] {error}", file=sys.stderr)
        return False

    finally:
        if connection is not None:
            connection.close()


def insert_alarm(
    tipo_alarma,
    ip_origen="N/A",
    modulo=None,
    descripcion=None,
    raw_data=None
):
    query = """
        INSERT INTO alarmas (
            tipo_alarma,
            ip_origen,
            modulo,
            descripcion,
            raw_data
        )
        VALUES (%s, %s, %s, %s, %s::jsonb)
    """

    params = (
        tipo_alarma,
        ip_origen or "N/A",
        modulo or "hips",
        descripcion,
        _json_or_none(raw_data)
    )

    return _safe_execute(query, params)


def insert_prevention(
    tipo_alarma,
    accion,
    resultado,
    ip_origen="N/A",
    raw_data=None
):
    query = """
        INSERT INTO acciones_prevencion (
            accion,
            resultado,
            tipo_alarma,
            ip_origen,
            raw_data
        )
        VALUES (%s, %s, %s, %s, %s::jsonb)
    """

    params = (
        accion,
        resultado,
        tipo_alarma,
        ip_origen or "N/A",
        _json_or_none(raw_data)
    )

    return _safe_execute(query, params)


def insert_event(
    modulo,
    tipo_evento,
    descripcion=None,
    raw_data=None
):
    query = """
        INSERT INTO eventos_sistema (
            evento,
            origen,
            detalle,
            raw_data
        )
        VALUES (%s, %s, %s, %s::jsonb)
    """

    params = (
        tipo_evento,
        modulo,
        descripcion,
        _json_or_none(raw_data)
    )

    return _safe_execute(query, params)
