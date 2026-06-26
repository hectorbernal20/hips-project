from collections import defaultdict
from datetime import datetime, timedelta
import argparse
import re

from alerts.logger import log_alarm
from alerts.mailer import send_admin_email
from prevention.firewall import block_ip


FAILED_LOGIN_REGEX = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2}).*Failed password.* from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

AUTH_FAILURE_REGEX = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2}).*authentication failure.*rhost=(?P<ip>\d+\.\d+\.\d+\.\d+)"
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


def read_failed_logins(log_path):
    events = []

    with open(log_path, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            match = FAILED_LOGIN_REGEX.search(line) or AUTH_FAILURE_REGEX.search(line)
            if not match:
                continue

            events.append({
                "timestamp": parse_syslog_datetime(
                    match.group("month"),
                    match.group("day"),
                    match.group("time")
                ),
                "ip": match.group("ip"),
                "raw": line.strip()
            })

    return events


def detect_failed_logins(log_path, threshold=5, window_minutes=10, whitelist=None):
    whitelist = whitelist or []
    events = read_failed_logins(log_path)
    events_by_ip = defaultdict(list)

    for event in events:
        if event["ip"] not in whitelist:
            events_by_ip[event["ip"]].append(event["timestamp"])

    alarms = []

    for ip, timestamps in events_by_ip.items():
        timestamps.sort()

        for index, start_time in enumerate(timestamps):
            end_time = start_time + timedelta(minutes=window_minutes)
            attempts = [ts for ts in timestamps[index:] if start_time <= ts <= end_time]

            if len(attempts) > threshold:
                alarms.append({
                    "tipo_alarma": "ACCESO_INVALIDO_REPETIDO",
                    "ip_origen": ip,
                    "modulo": "access_monitor",
                    "descripcion": f"{len(attempts)} intentos fallidos en {window_minutes} minutos"
                })
                break

    return alarms


def main():
    parser = argparse.ArgumentParser(description="Detector de intentos de acceso invalidos")
    parser.add_argument("--log", default="/var/log/secure")
    parser.add_argument("--threshold", type=int, default=5)
    parser.add_argument("--window", type=int, default=10)
    parser.add_argument("--prevent", action="store_true")
    parser.add_argument("--real-block", action="store_true")
    args = parser.parse_args()

    alarms = detect_failed_logins(args.log, args.threshold, args.window)

    for alarm in alarms:
        log_alarm(alarm["tipo_alarma"], alarm["ip_origen"])

        send_admin_email(
            f"[HIPS ALERTA] {alarm['tipo_alarma']}",
            f"Modulo: {alarm['modulo']}\nIP: {alarm['ip_origen']}\nDetalle: {alarm['descripcion']}"
        )

        if args.prevent:
            result = block_ip(
                alarm["ip_origen"],
                tipo_alarma=alarm["tipo_alarma"],
                dry_run=not args.real_block
            )
            print(f"Prevencion: {result}")

        print(alarm)

    if not alarms:
        print("No se detectaron accesos invalidos repetidos.")


if __name__ == "__main__":
    main()
