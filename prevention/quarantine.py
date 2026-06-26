import shutil
from datetime import datetime
from pathlib import Path

from alerts.logger import log_prevention
from alerts.mailer import send_admin_email


DEFAULT_QUARANTINE_DIR = Path("/var/lib/hips/quarantine")


def quarantine_file(
    file_path,
    tipo_alarma="ARCHIVO_TMP_SOSPECHOSO",
    quarantine_dir=DEFAULT_QUARANTINE_DIR,
    dry_run=True
):
    source = Path(file_path)
    quarantine_dir = Path(quarantine_dir)

    if not source.exists():
        resultado = f"No se pudo mover a cuarentena: archivo no existe {source}"

        log_prevention(tipo_alarma, "quarantine_file", resultado, "N/A")
        send_admin_email(f"[HIPS PREVENCION] {tipo_alarma}", resultado)

        return {
            "quarantined": False,
            "file": str(source),
            "reason": resultado
        }

    if dry_run:
        resultado = f"DRY RUN: se moveria a cuarentena {source}"

        log_prevention(tipo_alarma, "quarantine_file", resultado, "N/A")
        send_admin_email(f"[HIPS PREVENCION] {tipo_alarma}", resultado)

        return {
            "quarantined": False,
            "file": str(source),
            "reason": resultado
        }

    quarantine_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    destination = quarantine_dir / f"{timestamp}_{source.name}"

    shutil.move(str(source), str(destination))
    destination.chmod(0o600)

    resultado = f"Archivo movido a cuarentena: {source} -> {destination}"

    log_prevention(tipo_alarma, "quarantine_file", resultado, "N/A")
    send_admin_email(f"[HIPS PREVENCION] {tipo_alarma}", resultado)

    return {
        "quarantined": True,
        "file": str(source),
        "destination": str(destination),
        "reason": resultado
    }
