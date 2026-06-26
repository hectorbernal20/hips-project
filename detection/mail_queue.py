import argparse
import re
import subprocess
from collections import defaultdict
from pathlib import Path

from alerts.logger import log_alarm
from alerts.mailer import send_admin_email
from prevention.user_actions import lock_user, change_user_password
from prevention.service_mgmt import stop_service


QUEUE_LINE_REGEX = re.compile(
    r"^(?P<queue_id>[A-Za-z0-9]{5,}[*!]?)\s+"
    r"(?P<size>\d+)\s+"
    r".*\s+"
    r"(?P<sender>[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}|<>)$"
)


def read_mail_queue(sample_file=None):
    if sample_file:
        path = Path(sample_file)

        if not path.exists():
            return ""

        with path.open("r", encoding="utf-8", errors="ignore") as file:
            return file.read()

    try:
        result = subprocess.run(
            ["postqueue", "-p"],
            capture_output=True,
            text=True,
            check=False
        )
        return result.stdout + result.stderr
    except FileNotFoundError:
        return ""


def parse_mail_queue(queue_output):
    messages = []

    for line in queue_output.splitlines():
        clean_line = line.strip()

        if not clean_line:
            continue

        if "Mail queue is empty" in clean_line:
            continue

        match = QUEUE_LINE_REGEX.match(clean_line)

        if not match:
            continue

        sender = match.group("sender")

        messages.append({
            "queue_id": match.group("queue_id").rstrip("*!"),
            "size": int(match.group("size")),
            "sender": sender,
            "raw": clean_line
        })

    return messages


def detect_mail_queue_abuse(
    sample_file=None,
    queue_threshold=10,
    sender_threshold=5,
    size_threshold_kb=10240
):
    queue_output = read_mail_queue(sample_file)
    messages = parse_mail_queue(queue_output)

    total_messages = len(messages)
    total_size_bytes = sum(message["size"] for message in messages)
    total_size_kb = total_size_bytes // 1024

    messages_by_sender = defaultdict(list)

    for message in messages:
        messages_by_sender[message["sender"]].append(message)

    alarms = []

    if total_messages >= queue_threshold:
        alarms.append({
            "tipo_alarma": "MAIL_QUEUE_ALTA",
            "ip_origen": "N/A",
            "modulo": "mail_queue",
            "descripcion": (
                f"Cola de correo elevada: {total_messages} mensajes pendientes"
            ),
            "total_mensajes": total_messages,
            "total_kb": total_size_kb,
            "accion_preventiva": "stop_mail_service"
        })

    if total_size_kb >= size_threshold_kb:
        alarms.append({
            "tipo_alarma": "MAIL_QUEUE_TAMANIO_ALTO",
            "ip_origen": "N/A",
            "modulo": "mail_queue",
            "descripcion": (
                f"Cola de correo con tamano elevado: {total_size_kb} KB"
            ),
            "total_mensajes": total_messages,
            "total_kb": total_size_kb,
            "accion_preventiva": "stop_mail_service"
        })

    for sender, sender_messages in messages_by_sender.items():
        count = len(sender_messages)

        if sender == "<>":
            continue

        if count >= sender_threshold:
            username = sender.split("@")[0]

            alarms.append({
                "tipo_alarma": "MAIL_QUEUE_USUARIO_SOSPECHOSO",
                "ip_origen": "N/A",
                "modulo": "mail_queue",
                "usuario": username,
                "cuenta": sender,
                "descripcion": (
                    f"Cuenta con muchos mensajes en cola: {sender} "
                    f"({count} mensajes)"
                ),
                "total_mensajes": count,
                "accion_preventiva": "mail_user_action"
            })

    return alarms


def apply_prevention(alarm, dry_run=True, mail_action="lock_user"):
    action = alarm.get("accion_preventiva")

    if action == "stop_mail_service":
        stop_service(
            "postfix",
            tipo_alarma=alarm["tipo_alarma"],
            dry_run=dry_run
        )

        return {
            "service_action": "stop_postfix",
            "dry_run": dry_run
        }

    if action == "mail_user_action":
        username = alarm.get("usuario")

        if mail_action == "change_password":
            return change_user_password(
                username,
                tipo_alarma=alarm["tipo_alarma"],
                dry_run=dry_run
            )

        return lock_user(
            username,
            tipo_alarma=alarm["tipo_alarma"],
            dry_run=dry_run
        )

    return {
        "prevented": False,
        "reason": "No hay accion preventiva configurada"
    }


def notify_alarm(alarm):
    log_alarm(alarm["tipo_alarma"], alarm["ip_origen"])

    send_admin_email(
        f"[HIPS ALERTA] {alarm['tipo_alarma']}",
        (
            f"Modulo: {alarm['modulo']}\n"
            f"IP: {alarm['ip_origen']}\n"
            f"Detalle: {alarm['descripcion']}"
        )
    )


def main():
    parser = argparse.ArgumentParser(
        description="Modulo HIPS de monitoreo de cola de correo"
    )

    parser.add_argument(
        "--sample-file",
        help="Archivo con salida simulada de postqueue -p"
    )

    parser.add_argument(
        "--queue-threshold",
        type=int,
        default=10,
        help="Cantidad total de mensajes para alertar"
    )

    parser.add_argument(
        "--sender-threshold",
        type=int,
        default=5,
        help="Cantidad de mensajes por remitente para alertar"
    )

    parser.add_argument(
        "--size-threshold-kb",
        type=int,
        default=10240,
        help="Tamano total de cola en KB para alertar"
    )

    parser.add_argument("--prevent", action="store_true")
    parser.add_argument("--real-prevent", action="store_true")

    parser.add_argument(
        "--mail-action",
        choices=["lock_user", "change_password"],
        default="lock_user"
    )

    args = parser.parse_args()

    alarms = detect_mail_queue_abuse(
        sample_file=args.sample_file,
        queue_threshold=args.queue_threshold,
        sender_threshold=args.sender_threshold,
        size_threshold_kb=args.size_threshold_kb
    )

    for alarm in alarms:
        notify_alarm(alarm)

        if args.prevent:
            result = apply_prevention(
                alarm,
                dry_run=not args.real_prevent,
                mail_action=args.mail_action
            )
            print(f"Prevencion: {result}")

        print(alarm)

    if not alarms:
        print("No se detectaron anomalias en la cola de correo.")


if __name__ == "__main__":
    main()
