import argparse
import os
import re
import stat
from pathlib import Path

from alerts.logger import log_alarm
from alerts.mailer import send_admin_email
from prevention.cron_actions import disable_cron_file


DEFAULT_CRON_PATHS = [
    "/etc/crontab",
    "/etc/anacrontab",
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/var/spool/cron",
]

SUSPICIOUS_COMMAND_REGEX = re.compile(
    r"(/tmp/|/dev/shm/|/var/tmp/|"
    r"curl\s+|wget\s+|nc\s+|ncat\s+|netcat\s+|socat\s+|"
    r"bash\s+-i|sh\s+-i|python\s+-c|perl\s+-e|php\s+-r|"
    r"base64\s+-d|chmod\s+\+x|"
    r"reverse|payload|miner|backdoor|shell|exploit)",
    re.IGNORECASE
)

SUSPICIOUS_NAME_REGEX = re.compile(
    r"(^\.[A-Za-z0-9]{6,}$)|"
    r"([A-Za-z0-9]{12,})|"
    r"(payload|miner|backdoor|reverse|shell|exploit|malware)",
    re.IGNORECASE
)

CRON_SCHEDULE_REGEX = re.compile(
    r"^(@(reboot|hourly|daily|weekly|monthly|yearly|annually)|"
    r"(\S+\s+\S+\s+\S+\s+\S+\s+\S+))\s+"
)


def is_executable(file_path):
    try:
        file_stat = file_path.stat()
        return bool(file_stat.st_mode & stat.S_IXUSR)
    except OSError:
        return False


def collect_cron_files(paths):
    cron_files = []

    for raw_path in paths:
        path = Path(raw_path)

        if not path.exists():
            continue

        if path.is_file():
            cron_files.append(path)
            continue

        if path.is_dir():
            for item in path.rglob("*"):
                if item.is_file():
                    cron_files.append(item)

    return cron_files


def read_file_lines(file_path):
    try:
        with file_path.open("r", encoding="utf-8", errors="ignore") as file:
            return file.readlines()
    except OSError:
        return []


def is_comment_or_empty(line):
    clean_line = line.strip()
    return not clean_line or clean_line.startswith("#")


def detect_suspicious_cron_line(file_path, line_number, line):
    reasons = []
    clean_line = line.strip()

    if is_comment_or_empty(clean_line):
        return reasons

    if SUSPICIOUS_COMMAND_REGEX.search(clean_line):
        reasons.append("comando_o_ruta_sospechosa")

    if "/tmp/" in clean_line or "/dev/shm/" in clean_line or "/var/tmp/" in clean_line:
        reasons.append("ejecucion_desde_directorio_temporal")

    if re.search(r">/dev/null\s+2>&1", clean_line) and SUSPICIOUS_COMMAND_REGEX.search(clean_line):
        reasons.append("oculta_salida_de_comando_sospechoso")

    if CRON_SCHEDULE_REGEX.search(clean_line) and ("curl" in clean_line or "wget" in clean_line):
        reasons.append("descarga_remota_programada")

    return reasons


def detect_suspicious_cron_file(file_path):
    alarms = []

    file_reasons = []

    if SUSPICIOUS_NAME_REGEX.search(file_path.name):
        file_reasons.append("nombre_de_archivo_cron_sospechoso")

    if is_executable(file_path) and any(
        str(file_path).startswith(prefix)
        for prefix in ["/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"]
    ):
        file_reasons.append("script_cron_ejecutable")

    if file_reasons:
        alarms.append({
            "tipo_alarma": "CRON_ARCHIVO_SOSPECHOSO",
            "ip_origen": "N/A",
            "modulo": "cron_monitor",
            "archivo": str(file_path),
            "linea": "N/A",
            "descripcion": (
                f"Archivo cron sospechoso: {file_path}. "
                f"Motivos: {', '.join(file_reasons)}"
            ),
            "motivos": file_reasons
        })

    for index, line in enumerate(read_file_lines(file_path), start=1):
        line_reasons = detect_suspicious_cron_line(file_path, index, line)

        if not line_reasons:
            continue

        alarms.append({
            "tipo_alarma": "CRON_TAREA_SOSPECHOSA",
            "ip_origen": "N/A",
            "modulo": "cron_monitor",
            "archivo": str(file_path),
            "linea": index,
            "descripcion": (
                f"Tarea cron sospechosa en {file_path}:{index}. "
                f"Motivos: {', '.join(line_reasons)}. "
                f"Contenido: {line.strip()}"
            ),
            "motivos": line_reasons,
            "contenido": line.strip()
        })

    return alarms


def detect_cron_threats(paths=None):
    paths = paths or DEFAULT_CRON_PATHS
    alarms = []

    for cron_file in collect_cron_files(paths):
        alarms.extend(detect_suspicious_cron_file(cron_file))

    return alarms


def notify_alarm(alarm):
    log_alarm(alarm["tipo_alarma"], alarm["ip_origen"])

    send_admin_email(
        f"[HIPS ALERTA] {alarm['tipo_alarma']}",
        (
            f"Modulo: {alarm['modulo']}\n"
            f"Archivo: {alarm['archivo']}\n"
            f"Linea: {alarm['linea']}\n"
            f"Detalle: {alarm['descripcion']}"
        )
    )


def main():
    parser = argparse.ArgumentParser(
        description="Modulo HIPS de monitoreo de archivos cron"
    )

    parser.add_argument(
        "--cron-path",
        action="append",
        dest="cron_paths",
        help="Archivo o directorio cron a analizar. Puede repetirse."
    )

    parser.add_argument("--prevent", action="store_true")
    parser.add_argument("--real-prevent", action="store_true")
    parser.add_argument(
        "--quarantine-dir",
        default="/var/lib/hips/quarantine/cron"
    )

    args = parser.parse_args()

    alarms = detect_cron_threats(args.cron_paths)

    for alarm in alarms:
        notify_alarm(alarm)

        if args.prevent:
            result = disable_cron_file(
                alarm["archivo"],
                tipo_alarma=alarm["tipo_alarma"],
                quarantine_dir=args.quarantine_dir,
                dry_run=not args.real_prevent
            )
            print(f"Prevencion: {result}")

        print(alarm)

    if not alarms:
        print("No se detectaron tareas cron sospechosas.")


if __name__ == "__main__":
    main()
