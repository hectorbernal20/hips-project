import argparse
import re
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

from alerts.logger import log_alarm
from alerts.mailer import send_admin_email
from prevention.firewall import block_ip
from prevention.user_actions import lock_user, change_user_password
from prevention.service_mgmt import stop_service


IP_REGEX = r"(?P<ip>\d+\.\d+\.\d+\.\d+)"

FAILED_PASSWORD_REGEX = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2}).*Failed password.* from " + IP_REGEX
)

AUTH_FAILURE_REGEX = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2}).*authentication failure.*rhost=" + IP_REGEX
)

INVALID_USER_REGEX = re.compile(
    r"Invalid user (?P<user>\S+) from " + IP_REGEX
)

HTTP_ACCESS_REGEX = re.compile(
    r"^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+"
    r'"(?P<method>\S+)\s+(?P<path>\S+).*"\s+(?P<status>\d{3})'
)

MAIL_FROM_REGEX = re.compile(
    r"from=<(?P<account>[^>]+)>|sasl_username=(?P<sasl>\S+)"
)

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def parse_syslog_datetime(month, day, time_value):
    current_year = datetime.now().year
    hour, minute, second = map(int, time_value.split(":"))
    return datetime(current_year, MONTHS[month], int(day), hour, minute, second)


def read_lines(log_path):
    path = Path(log_path)

    if not path.exists():
        return []

    with path.open("r", encoding="utf-8", errors="ignore") as file:
        return file.readlines()


def detect_auth_abuse(log_paths, threshold=5, window_minutes=10):
    events_by_ip = defaultdict(list)
    users_by_ip = defaultdict(set)

    for log_path in log_paths:
        for line in read_lines(log_path):
            match = FAILED_PASSWORD_REGEX.search(line) or AUTH_FAILURE_REGEX.search(line)

            if match:
                timestamp = parse_syslog_datetime(
                    match.group("month"),
                    match.group("day"),
                    match.group("time")
                )
                ip = match.group("ip")
                events_by_ip[ip].append(timestamp)

            invalid_user_match = INVALID_USER_REGEX.search(line)

            if invalid_user_match:
                users_by_ip[invalid_user_match.group("ip")].add(
                    invalid_user_match.group("user")
                )

    alarms = []

    for ip, timestamps in events_by_ip.items():
        timestamps.sort()

        for index, start_time in enumerate(timestamps):
            end_time = start_time + timedelta(minutes=window_minutes)
            attempts = [
                ts for ts in timestamps[index:]
                if start_time <= ts <= end_time
            ]

            if len(attempts) >= threshold:
                alarms.append({
                    "tipo_alarma": "LOG_AUTH_ABUSO",
                    "ip_origen": ip,
                    "modulo": "log_analyzer",
                    "descripcion": (
                        f"{len(attempts)} fallos de autenticacion en "
                        f"{window_minutes} minutos"
                    ),
                    "accion_preventiva": "block_ip"
                })
                break

    for ip, users in users_by_ip.items():
        if len(users) >= 3:
            alarms.append({
                "tipo_alarma": "CREDENTIAL_STUFFING_DETECTADO",
                "ip_origen": ip,
                "modulo": "log_analyzer",
                "descripcion": (
                    f"Intentos con multiples usuarios desde una misma IP: "
                    f"{', '.join(sorted(users))}"
                ),
                "accion_preventiva": "block_ip"
            })

    return alarms


def detect_http_scanner(access_log, threshold=10):
    errors_by_ip = defaultdict(list)

    for line in read_lines(access_log):
        match = HTTP_ACCESS_REGEX.search(line)

        if not match:
            continue

        status = int(match.group("status"))
        ip = match.group("ip")
        path = match.group("path")

        if status in {400, 401, 403, 404, 405, 500}:
            errors_by_ip[ip].append({
                "status": status,
                "path": path,
                "raw": line.strip()
            })

    alarms = []

    for ip, errors in errors_by_ip.items():
        if len(errors) >= threshold:
            alarms.append({
                "tipo_alarma": "POSIBLE_SCANNER_HTTP",
                "ip_origen": ip,
                "modulo": "log_analyzer",
                "descripcion": (
                    f"{len(errors)} errores HTTP desde la misma IP. "
                    f"Posible scanner web."
                ),
                "accion_preventiva": "block_ip"
            })

    return alarms


def extract_mail_account(line):
    match = MAIL_FROM_REGEX.search(line)

    if not match:
        return None

    return match.group("account") or match.group("sasl")


def detect_mass_mail(maillog, threshold=20):
    sent_by_account = defaultdict(int)

    for line in read_lines(maillog):
        if "from=<" not in line and "sasl_username=" not in line:
            continue

        account = extract_mail_account(line)

        if not account:
            continue

        if "status=sent" in line or "from=<" in line:
            sent_by_account[account] += 1

    alarms = []

    for account, count in sent_by_account.items():
        if count >= threshold:
            username = account.split("@")[0]

            alarms.append({
                "tipo_alarma": "ENVIO_MASIVO_MAILS",
                "ip_origen": "N/A",
                "modulo": "log_analyzer",
                "usuario": username,
                "cuenta": account,
                "descripcion": (
                    f"Cuenta con posible envio masivo de correo: "
                    f"{account} ({count} eventos)"
                ),
                "accion_preventiva": "mail_user_action"
            })

    return alarms


def analyze_logs(
    secure_log="/var/log/secure",
    messages_log="/var/log/messages",
    http_access_log="/var/log/httpd/access.log",
    maillog="/var/log/maillog",
    auth_threshold=5,
    auth_window=10,
    http_threshold=10,
    mail_threshold=20
):
    alarms = []

    alarms.extend(
        detect_auth_abuse(
            [secure_log, messages_log],
            threshold=auth_threshold,
            window_minutes=auth_window
        )
    )

    alarms.extend(
        detect_http_scanner(
            http_access_log,
            threshold=http_threshold
        )
    )

    alarms.extend(
        detect_mass_mail(
            maillog,
            threshold=mail_threshold
        )
    )

    return alarms


def apply_prevention(alarm, dry_run=True, mail_action="lock_user"):
    tipo_alarma = alarm["tipo_alarma"]

    if alarm["accion_preventiva"] == "block_ip":
        return block_ip(
            alarm["ip_origen"],
            tipo_alarma=tipo_alarma,
            dry_run=dry_run
        )

    if alarm["accion_preventiva"] == "mail_user_action":
        username = alarm.get("usuario")

        if mail_action == "change_password":
            return change_user_password(
                username,
                tipo_alarma=tipo_alarma,
                dry_run=dry_run
            )

        if mail_action == "stop_mail_service":
            stop_service(
                "postfix",
                tipo_alarma=tipo_alarma,
                dry_run=dry_run
            )
            return {
                "service_action": "stop_postfix",
                "dry_run": dry_run
            }

        return lock_user(
            username,
            tipo_alarma=tipo_alarma,
            dry_run=dry_run
        )

    return {
        "prevented": False,
        "reason": "No hay accion preventiva configurada"
    }


def main():
    parser = argparse.ArgumentParser(
        description="Modulo HIPS de analisis de logs del sistema"
    )

    parser.add_argument("--secure-log", default="/var/log/secure")
    parser.add_argument("--messages-log", default="/var/log/messages")
    parser.add_argument("--http-access-log", default="/var/log/httpd/access.log")
    parser.add_argument("--maillog", default="/var/log/maillog")

    parser.add_argument("--auth-threshold", type=int, default=5)
    parser.add_argument("--auth-window", type=int, default=10)
    parser.add_argument("--http-threshold", type=int, default=10)
    parser.add_argument("--mail-threshold", type=int, default=20)

    parser.add_argument("--prevent", action="store_true")
    parser.add_argument("--real-prevent", action="store_true")

    parser.add_argument(
        "--mail-action",
        choices=["lock_user", "change_password", "stop_mail_service"],
        default="lock_user"
    )

    args = parser.parse_args()

    alarms = analyze_logs(
        secure_log=args.secure_log,
        messages_log=args.messages_log,
        http_access_log=args.http_access_log,
        maillog=args.maillog,
        auth_threshold=args.auth_threshold,
        auth_window=args.auth_window,
        http_threshold=args.http_threshold,
        mail_threshold=args.mail_threshold
    )

    for alarm in alarms:
        log_alarm(alarm["tipo_alarma"], alarm["ip_origen"])

        send_admin_email(
            f"[HIPS ALERTA] {alarm['tipo_alarma']}",
            (
                f"Modulo: {alarm['modulo']}\n"
                f"IP: {alarm['ip_origen']}\n"
                f"Detalle: {alarm['descripcion']}"
            )
        )

        if args.prevent:
            result = apply_prevention(
                alarm,
                dry_run=not args.real_prevent,
                mail_action=args.mail_action
            )
            print(f"Prevencion: {result}")

        print(alarm)

    if not alarms:
        print("No se detectaron eventos sospechosos en logs.")


if __name__ == "__main__":
    main()
