from pathlib import Path
from datetime import datetime
import shutil

from alerts.logger import log_prevention
from alerts.mailer import send_admin_email


PROTECTED_CRON_FILES = {
    "/etc/crontab",
    "/etc/anacrontab"
}

DEFAULT_CRON_QUARANTINE_DIR = Path("/var/lib/hips/quarantine/cron")


def disable_cron_file(
    cron_file,
    tipo_alarma="CRON_SOSPECHOSO",
    quarantine_dir=DEFAULT_CRON_QUARANTINE_DIR,
    dry_run=True
):
    source = Path(cron_file)
    quarantine_dir = Path(quarantine_dir)

    if not source.exists():
        resultado = f"No se pudo deshabilitar cron: archivo no existe {source}"

        log_prevention(tipo_alarma, "disable_cron_file", resultado, "N/A")
        send_admin_email(f"[HIPS PREVENCION] {tipo_alarma}", resultado)

        return {
            "disabled": False,
            "file": str(source),
            "reason": resultado
        }

    if str(source) in PROTECTED_CRON_FILES:
        resultado = (
            f"Archivo cron protegido, no se mueve automaticamente: {source}. "
            "Requiere revision manual."
        )

        log_prevention(tipo_alarma, "disable_cron_file", resultado, "N/A")
        send_admin_email(f"[HIPS PREVENCION] {tipo_alarma}", resultado)

        return {
            "disabled": False,
            "file": str(source),
            "reason": resultado
        }

    if dry_run:
        resultado = f"DRY RUN: se moveria cron sospechoso a cuarentena: {source}"

        log_prevention(tipo_alarma, "disable_cron_file", resultado, "N/A")
        send_admin_email(f"[HIPS PREVENCION] {tipo_alarma}", resultado)

        return {
            "disabled": False,
            "file": str(source),
            "reason": resultado
        }

    quarantine_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    destination = quarantine_dir / f"{timestamp}_{source.name}"

    shutil.move(str(source), str(destination))
    destination.chmod(0o600)

    resultado = f"Cron sospechoso movido a cuarentena: {source} -> {destination}"

    log_prevention(tipo_alarma, "disable_cron_file", resultado, "N/A")
    send_admin_email(f"[HIPS PREVENCION] {tipo_alarma}", resultado)

    return {
        "disabled": True,
        "file": str(source),
        "destination": str(destination),
        "reason": resultado
    }
