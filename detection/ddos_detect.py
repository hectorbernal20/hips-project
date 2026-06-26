import argparse
import re
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

from alerts.logger import log_alarm
from alerts.mailer import send_admin_email
from prevention.firewall import block_ip
from prevention.service_mgmt import stop_service


DNS_QUERY_REGEX = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2}).*client\s+"
    r"(?P<ip>\d+\.\d+\.\d+\.\d+)#\d+.*query:\s+"
    r"(?P<domain>\S+)\s+IN\s+(?P<qtype>\S+)",
    re.IGNORECASE
)

GENERIC_IP_REGEX = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2}).*"
    r"(?P<ip>\d+\.\d+\.\d+\.\d+)"
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


def parse_dns_events(log_path):
    events = []

    for line in read_lines(log_path):
        dns_match = DNS_QUERY_REGEX.search(line)

        if dns_match:
            events.append({
                "timestamp": parse_syslog_datetime(
                    dns_match.group("month"),
                    dns_match.group("day"),
                    dns_match.group("time")
                ),
                "ip": dns_match.group("ip"),
                "domain": dns_match.group("domain"),
                "qtype": dns_match.group("qtype").upper(),
                "raw": line.strip()
            })
            continue

        generic_match = GENERIC_IP_REGEX.search(line)

        if generic_match:
            events.append({
                "timestamp": parse_syslog_datetime(
                    generic_match.group("month"),
                    generic_match.group("day"),
                    generic_match.group("time")
                ),
                "ip": generic_match.group("ip"),
                "domain": "N/A",
                "qtype": "UNKNOWN",
                "raw": line.strip()
            })

    return events


def count_events_in_window(timestamps, window_seconds):
    timestamps.sort()

    max_count = 0

    for index, start_time in enumerate(timestamps):
        end_time = start_time + timedelta(seconds=window_seconds)
        count = sum(1 for ts in timestamps[index:] if start_time <= ts <= end_time)
        max_count = max(max_count, count)

    return max_count


def detect_ddos(
    log_path,
    ip_threshold=50,
    global_threshold=200,
    window_seconds=60,
    any_threshold=20
):
    events = parse_dns_events(log_path)

    events_by_ip = defaultdict(list)
    any_queries_by_ip = defaultdict(list)
    all_timestamps = []

    for event in events:
        events_by_ip[event["ip"]].append(event["timestamp"])
        all_timestamps.append(event["timestamp"])

        if event["qtype"] == "ANY":
            any_queries_by_ip[event["ip"]].append(event["timestamp"])

    alarms = []

    for ip, timestamps in events_by_ip.items():
        max_count = count_events_in_window(timestamps, window_seconds)

        if max_count >= ip_threshold:
            alarms.append({
                "tipo_alarma": "DDOS_DNS_IP_ALTA_FRECUENCIA",
                "ip_origen": ip,
                "modulo": "ddos_detect",
                "descripcion": (
                    f"{max_count} eventos DNS desde {ip} en "
                    f"{window_seconds} segundos"
                ),
                "accion_preventiva": "block_ip"
            })

    for ip, timestamps in any_queries_by_ip.items():
        max_count = count_events_in_window(timestamps, window_seconds)

        if max_count >= any_threshold:
            alarms.append({
                "tipo_alarma": "DDOS_DNS_ANY_FLOOD",
                "ip_origen": ip,
                "modulo": "ddos_detect",
                "descripcion": (
                    f"{max_count} consultas DNS tipo ANY desde {ip} en "
                    f"{window_seconds} segundos"
                ),
                "accion_preventiva": "block_ip"
            })

    global_count = count_events_in_window(all_timestamps, window_seconds)

    if global_count >= global_threshold:
        alarms.append({
            "tipo_alarma": "DDOS_DNS_DISTRIBUIDO",
            "ip_origen": "N/A",
            "modulo": "ddos_detect",
            "descripcion": (
                f"{global_count} eventos DNS totales en "
                f"{window_seconds} segundos. Posible DDoS distribuido."
            ),
            "accion_preventiva": "stop_dns_service"
        })

    return alarms


def apply_prevention(alarm, dry_run=True, dns_service="named"):
    if alarm["accion_preventiva"] == "block_ip":
        return block_ip(
            alarm["ip_origen"],
            tipo_alarma=alarm["tipo_alarma"],
            dry_run=dry_run
        )

    if alarm["accion_preventiva"] == "stop_dns_service":
        stop_service(
            dns_service,
            tipo_alarma=alarm["tipo_alarma"],
            dry_run=dry_run
        )

        return {
            "service_action": "stop_service",
            "service": dns_service,
            "dry_run": dry_run
        }

    return {
        "prevented": False,
        "reason": "No hay accion preventiva configurada"
    }


def main():
    parser = argparse.ArgumentParser(
        description="Modulo HIPS de deteccion de ataques DDoS sobre DNS"
    )

    parser.add_argument(
        "--log",
        default="/var/log/messages",
        help="Log DNS o log simulado a analizar"
    )

    parser.add_argument(
        "--ip-threshold",
        type=int,
        default=50,
        help="Eventos por IP dentro de la ventana"
    )

    parser.add_argument(
        "--global-threshold",
        type=int,
        default=200,
        help="Eventos globales dentro de la ventana"
    )

    parser.add_argument(
        "--any-threshold",
        type=int,
        default=20,
        help="Consultas DNS tipo ANY por IP dentro de la ventana"
    )

    parser.add_argument(
        "--window",
        type=int,
        default=60,
        help="Ventana de tiempo en segundos"
    )

    parser.add_argument(
        "--dns-service",
        default="named",
        help="Servicio DNS a detener si hay DDoS distribuido"
    )

    parser.add_argument("--prevent", action="store_true")
    parser.add_argument("--real-prevent", action="store_true")

    args = parser.parse_args()

    alarms = detect_ddos(
        args.log,
        ip_threshold=args.ip_threshold,
        global_threshold=args.global_threshold,
        window_seconds=args.window,
        any_threshold=args.any_threshold
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
                dns_service=args.dns_service
            )
            print(f"Prevencion: {result}")

        print(alarm)

    if not alarms:
        print("No se detectaron patrones de DDoS DNS.")


if __name__ == "__main__":
    main()
