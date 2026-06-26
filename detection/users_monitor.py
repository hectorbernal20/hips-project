import argparse
import ipaddress
import re
import subprocess
from datetime import datetime

from alerts.logger import log_alarm
from alerts.mailer import send_admin_email
from prevention.user_actions import lock_user, force_logout_user


WHO_REGEX = re.compile(
    r"^(?P<user>\S+)\s+"
    r"(?P<tty>\S+)\s+"
    r"(?P<date>\d{4}-\d{2}-\d{2})\s+"
    r"(?P<time>\d{2}:\d{2})"
    r"(?:\s+\((?P<origin>[^)]+)\))?"
)


DEFAULT_ALLOWED_USERS = {
    "hector"
}

DEFAULT_ALLOWED_ORIGINS = {
    "localhost",
    "127.0.0.1",
    "192.168.56.1"
}

DEFAULT_ALLOWED_NETWORKS = [
    "192.168.56.0/24"
]


def read_who_output(sample_file=None):
    if sample_file:
        with open(sample_file, "r", encoding="utf-8", errors="ignore") as file:
            return file.read()

    result = subprocess.run(
        ["who"],
        capture_output=True,
        text=True,
        check=True
    )

    return result.stdout


def parse_who_output(output):
    sessions = []

    for line in output.splitlines():
        line = line.strip()

        if not line:
            continue

        match = WHO_REGEX.match(line)

        if not match:
            continue

        origin = match.group("origin") or "LOCAL"

        sessions.append({
            "user": match.group("user"),
            "tty": match.group("tty"),
            "date": match.group("date"),
            "time": match.group("time"),
            "origin": origin,
            "raw": line
        })

    return sessions


def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def origin_allowed(origin, allowed_origins, allowed_networks):
    if origin in allowed_origins:
        return True

    if origin == "LOCAL":
        return True

    if not is_ip(origin):
        return False

    ip_value = ipaddress.ip_address(origin)

    for network in allowed_networks:
        if ip_value in ipaddress.ip_network(network, strict=False):
            return True

    return False


def is_inside_allowed_hours(current_hour, start_hour, end_hour):
    if start_hour == end_hour:
        return True

    if start_hour < end_hour:
        return start_hour <= current_hour < end_hour

    return current_hour >= start_hour or current_hour < end_hour


def detect_user_sessions(
    sample_file=None,
    allowed_users=None,
    allowed_origins=None,
    allowed_networks=None,
    start_hour=6,
    end_hour=23
):
    allowed_users = set(allowed_users or DEFAULT_ALLOWED_USERS)
    allowed_origins = set(allowed_origins or DEFAULT_ALLOWED_ORIGINS)
    allowed_networks = list(allowed_networks or DEFAULT_ALLOWED_NETWORKS)

    output = read_who_output(sample_file)
    sessions = parse_who_output(output)

    alarms = []
    current_hour = datetime.now().hour

    for session in sessions:
        user = session["user"]
        origin = session["origin"]

        if user not in allowed_users:
            alarms.append({
                "tipo_alarma": "USUARIO_NO_AUTORIZADO_CONECTADO",
                "ip_origen": origin if is_ip(origin) else "N/A",
                "modulo": "users_monitor",
                "usuario": user,
                "descripcion": f"Usuario conectado no autorizado: {user}",
                "session": session
            })

        if not origin_allowed(origin, allowed_origins, allowed_networks):
            alarms.append({
                "tipo_alarma": "ORIGEN_USUARIO_INUSUAL",
                "ip_origen": origin if is_ip(origin) else "N/A",
                "modulo": "users_monitor",
                "usuario": user,
                "descripcion": f"Origen inusual para usuario {user}: {origin}",
                "session": session
            })

        if not is_inside_allowed_hours(current_hour, start_hour, end_hour):
            alarms.append({
                "tipo_alarma": "USUARIO_FUERA_DE_HORARIO",
                "ip_origen": origin if is_ip(origin) else "N/A",
                "modulo": "users_monitor",
                "usuario": user,
                "descripcion": (
                    f"Usuario {user} conectado fuera de horario permitido "
                    f"({start_hour}:00-{end_hour}:00)"
                ),
                "session": session
            })

    return alarms


def main():
    parser = argparse.ArgumentParser(
        description="Modulo HIPS de usuarios conectados"
    )

    parser.add_argument(
        "--sample-file",
        help="Archivo de prueba con salida simulada del comando who"
    )

    parser.add_argument(
        "--allowed-user",
        action="append",
        dest="allowed_users",
        help="Usuario permitido. Puede repetirse."
    )

    parser.add_argument(
        "--allowed-origin",
        action="append",
        dest="allowed_origins",
        help="Origen permitido. Puede repetirse."
    )

    parser.add_argument(
        "--allowed-network",
        action="append",
        dest="allowed_networks",
        help="Red permitida. Ejemplo: 192.168.56.0/24"
    )

    parser.add_argument("--start-hour", type=int, default=6)
    parser.add_argument("--end-hour", type=int, default=23)
    parser.add_argument("--prevent", action="store_true")
    parser.add_argument("--real-prevent", action="store_true")
    parser.add_argument(
        "--force-logout",
        action="store_true",
        help="Ademas de bloquear usuario, intenta cerrar su sesion"
    )

    args = parser.parse_args()

    alarms = detect_user_sessions(
        sample_file=args.sample_file,
        allowed_users=args.allowed_users,
        allowed_origins=args.allowed_origins,
        allowed_networks=args.allowed_networks,
        start_hour=args.start_hour,
        end_hour=args.end_hour
    )

    for alarm in alarms:
        log_alarm(alarm["tipo_alarma"], alarm["ip_origen"])

        send_admin_email(
            f"[HIPS ALERTA] {alarm['tipo_alarma']}",
            (
                f"Modulo: {alarm['modulo']}\n"
                f"Usuario: {alarm['usuario']}\n"
                f"IP/Origen: {alarm['ip_origen']}\n"
                f"Detalle: {alarm['descripcion']}"
            )
        )

        if args.prevent:
            result = lock_user(
                alarm["usuario"],
                tipo_alarma=alarm["tipo_alarma"],
                dry_run=not args.real_prevent
            )
            print(f"Prevencion: {result}")

            if args.force_logout:
                logout_result = force_logout_user(
                    alarm["usuario"],
                    tipo_alarma=alarm["tipo_alarma"],
                    dry_run=not args.real_prevent
                )
                print(f"Logout: {logout_result}")

        print(alarm)

    if not alarms:
        print("No se detectaron usuarios conectados sospechosos.")


if __name__ == "__main__":
    main()
