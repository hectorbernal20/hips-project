import os
import signal
import subprocess

from alerts.logger import log_prevention
from alerts.mailer import send_admin_email


PROTECTED_PIDS = {
    "1"
}


def kill_process(pid, process_name, tipo_alarma="SNIFFER_DETECTADO", dry_run=True):
    pid = str(pid)

    if pid in PROTECTED_PIDS:
        resultado = f"PID protegido, no se termina: {pid}"

        log_prevention(tipo_alarma, "kill_sniffer_process", resultado, "N/A")
        send_admin_email(f"[HIPS PREVENCION] {tipo_alarma}", resultado)

        return {
            "killed": False,
            "pid": pid,
            "process": process_name,
            "reason": resultado
        }

    if dry_run:
        resultado = f"DRY RUN: se terminaria proceso sniffer {process_name} con PID {pid}"
    else:
        os.kill(int(pid), signal.SIGTERM)
        resultado = f"Proceso sniffer terminado: {process_name} PID {pid}"

    log_prevention(tipo_alarma, "kill_sniffer_process", resultado, "N/A")
    send_admin_email(f"[HIPS PREVENCION] {tipo_alarma}", resultado)

    return {
        "killed": not dry_run,
        "pid": pid,
        "process": process_name,
        "reason": resultado
    }


def disable_promiscuous_mode(interface, tipo_alarma="MODO_PROMISCUO_DETECTADO", dry_run=True):
    if dry_run:
        resultado = f"DRY RUN: se desactivaria modo promiscuo en interfaz {interface}"
    else:
        subprocess.run(["ip", "link", "set", interface, "promisc", "off"], check=True)
        resultado = f"Modo promiscuo desactivado en interfaz {interface}"

    log_prevention(tipo_alarma, "disable_promiscuous_mode", resultado, "N/A")
    send_admin_email(f"[HIPS PREVENCION] {tipo_alarma}", resultado)

    return {
        "disabled": not dry_run,
        "interface": interface,
        "reason": resultado
    }
