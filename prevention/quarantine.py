from pathlib import Path
import shutil

from alerts.logger import log_prevention
from alerts.mailer import send_admin_email


QUARANTINE_DIR = Path("/var/log/hips/quarantine")


def quarantine_file(path, tipo_alarma="ARCHIVO_SOSPECHOSO", dry_run=True):
    source = Path(path)

    if dry_run:
        resultado = f"DRY RUN: se moveria {source} a cuarentena"
    else:
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        target = QUARANTINE_DIR / source.name
        shutil.move(str(source), str(target))
        resultado = f"Archivo movido a cuarentena: {target}"

    log_prevention(tipo_alarma, "quarantine_file", resultado, "N/A")
    send_admin_email(f"[HIPS PREVENCION] {tipo_alarma}", resultado)

    return resultado
