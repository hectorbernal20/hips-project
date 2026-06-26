import os
import signal

from alerts.logger import log_prevention
from alerts.mailer import send_admin_email


def kill_process(pid, tipo_alarma="PROCESO_SOSPECHOSO", dry_run=True):
    if dry_run:
        resultado = f"DRY RUN: se terminaria el proceso PID {pid}"
    else:
        os.kill(int(pid), signal.SIGTERM)
        resultado = f"Proceso terminado PID {pid}"

    log_prevention(tipo_alarma, "kill_process", resultado, "N/A")
    send_admin_email(f"[HIPS PREVENCION] {tipo_alarma}", resultado)

    return resultado
