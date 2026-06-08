from datetime import datetime
from pathlib import Path
import os


def log_alarm(tipo_alarma, ip_origen, modulo, descripcion, accion_tomada="N/A", log_file=None):
    log_dir = Path(os.getenv("HIPS_LOG_DIR", "/var/log/hips"))
    log_dir.mkdir(parents=True, exist_ok=True)

    target = Path(log_file) if log_file else log_dir / "alarmas.log"

    timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    line = f"{timestamp} :: {tipo_alarma} :: {ip_origen} :: {modulo} :: {accion_tomada} :: {descripcion}\n"

    with target.open("a", encoding="utf-8") as f:
        f.write(line)

    return line
