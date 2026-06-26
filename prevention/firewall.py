import subprocess

from alerts.logger import log_prevention
from alerts.mailer import send_admin_email


DEFAULT_WHITELIST = {
    "127.0.0.1",
    "localhost",
    "192.168.56.1"
}


def block_ip(ip_address, tipo_alarma="IP_SOSPECHOSA", dry_run=True, whitelist=None):
    whitelist = whitelist or DEFAULT_WHITELIST

    command = [
        "firewall-cmd",
        "--permanent",
        "--add-rich-rule",
        f"rule family='ipv4' source address='{ip_address}' reject"
    ]

    command_text = " ".join(command)

    if ip_address in whitelist:
        resultado = "IP en whitelist, no se bloquea"

        log_prevention(tipo_alarma, "block_ip", resultado, ip_address)
        send_admin_email(
            f"[HIPS PREVENCION] {tipo_alarma}",
            f"No se bloqueo la IP {ip_address}. Motivo: {resultado}"
        )

        return {
            "blocked": False,
            "ip": ip_address,
            "reason": resultado,
            "command": None
        }

    if dry_run:
        resultado = f"DRY RUN: se bloquearia la IP {ip_address}"

        log_prevention(tipo_alarma, "block_ip", resultado, ip_address)
        send_admin_email(
            f"[HIPS PREVENCION] {tipo_alarma}",
            resultado
        )

        return {
            "blocked": False,
            "ip": ip_address,
            "reason": resultado,
            "command": command_text
        }

    subprocess.run(command, check=True)
    subprocess.run(["firewall-cmd", "--reload"], check=True)

    resultado = f"IP bloqueada: {ip_address}"

    log_prevention(tipo_alarma, "block_ip", resultado, ip_address)
    send_admin_email(
        f"[HIPS PREVENCION] {tipo_alarma}",
        resultado
    )

    return {
        "blocked": True,
        "ip": ip_address,
        "reason": resultado,
        "command": command_text
    }
