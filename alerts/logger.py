from datetime import datetime
from pathlib import Path
import os


LOG_DIR = Path(os.getenv("HIPS_LOG_DIR", "/var/log/hips"))


def _ensure_log_dir():
    LOG_DIR.mkdir(parents=True, exist_ok=True)


def current_timestamp():
    return datetime.now().strftime("%d/%m/%Y %H:%M:%S")


def log_alarm(tipo_alarma, ip_origen="N/A"):
    """
    Formato obligatorio del TP:
    timestamp :: Tipo de Alarma :: IP origen
    """
    _ensure_log_dir()
    line = f"{current_timestamp()} :: {tipo_alarma} :: {ip_origen or 'N/A'}\n"

    with (LOG_DIR / "alarmas.log").open("a", encoding="utf-8") as file:
        file.write(line)

    return line


def log_prevention(tipo_alarma, accion, resultado, ip_origen="N/A"):
    """
    Registro de acciones tomadas por el módulo de prevención.
    """
    _ensure_log_dir()
    line = (
        f"{current_timestamp()} :: {tipo_alarma} :: {ip_origen or 'N/A'} "
        f":: {accion} :: {resultado}\n"
    )

    with (LOG_DIR / "prevencion.log").open("a", encoding="utf-8") as file:
        file.write(line)

    return line
