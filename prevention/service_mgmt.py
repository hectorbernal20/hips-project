import subprocess

from alerts.logger import log_prevention
from alerts.mailer import send_admin_email


def stop_service(service_name, tipo_alarma="SERVICIO_COMPROMETIDO", dry_run=True):
    if dry_run:
        resultado = f"DRY RUN: se detendria el servicio {service_name}"
    else:
        subprocess.run(["systemctl", "stop", service_name], check=True)
        resultado = f"Servicio detenido: {service_name}"

    log_prevention(tipo_alarma, "stop_service", resultado, "N/A")
    send_admin_email(f"[HIPS PREVENCION] {tipo_alarma}", resultado)

    return resultado
