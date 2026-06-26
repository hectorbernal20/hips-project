import os
import signal

from alerts.logger import log_prevention
from alerts.mailer import send_admin_email


PROTECTED_USERS = {
    "root",
    "hector",
    "postgres"
}

PROTECTED_PROCESS_NAMES = {
    "systemd",
    "sshd",
    "bash",
    "python",
    "python3",
    "postgres",
    "flask"
}

PROTECTED_PIDS = {
    "1"
}


def terminate_process(
    pid,
    process_name,
    process_user,
    tipo_alarma="PROCESO_ALTO_CONSUMO",
    dry_run=True,
    force=False
):
    pid = str(pid)
    process_name = str(process_name)
    process_user = str(process_user)

    if pid in PROTECTED_PIDS:
        resultado = f"PID protegido, no se termina: {pid}"
        log_prevention(tipo_alarma, "terminate_process", resultado, "N/A")
        send_admin_email(f"[HIPS PREVENCION] {tipo_alarma}", resultado)
        return {"terminated": False, "pid": pid, "reason": resultado}

    if process_user in PROTECTED_USERS and not force:
        resultado = (
            f"Usuario protegido, no se termina proceso {process_name} "
            f"PID {pid}. Use --force-kill para permitirlo."
        )
        log_prevention(tipo_alarma, "terminate_process", resultado, "N/A")
        send_admin_email(f"[HIPS PREVENCION] {tipo_alarma}", resultado)
        return {"terminated": False, "pid": pid, "reason": resultado}

    if process_name in PROTECTED_PROCESS_NAMES and not force:
        resultado = (
            f"Proceso protegido, no se termina: {process_name} PID {pid}. "
            f"Use --force-kill para permitirlo."
        )
        log_prevention(tipo_alarma, "terminate_process", resultado, "N/A")
        send_admin_email(f"[HIPS PREVENCION] {tipo_alarma}", resultado)
        return {"terminated": False, "pid": pid, "reason": resultado}

    if dry_run:
        resultado = f"DRY RUN: se terminaria proceso {process_name} PID {pid}"
    else:
        os.kill(int(pid), signal.SIGTERM)
        resultado = f"Proceso terminado: {process_name} PID {pid}"

    log_prevention(tipo_alarma, "terminate_process", resultado, "N/A")
    send_admin_email(f"[HIPS PREVENCION] {tipo_alarma}", resultado)

    return {
        "terminated": not dry_run,
        "pid": pid,
        "process": process_name,
        "user": process_user,
        "reason": resultado
    }
