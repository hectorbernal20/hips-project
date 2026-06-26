import argparse
import os
import re
import stat
import subprocess
from pathlib import Path

from alerts.logger import log_alarm
from alerts.mailer import send_admin_email
from prevention.quarantine import quarantine_file
from prevention.process_kill import terminate_process


SUSPICIOUS_EXTENSIONS = {
    ".sh",
    ".py",
    ".pl",
    ".php",
    ".rb",
    ".elf",
    ".bin",
    ".run",
    ".out"
}

SUSPICIOUS_NAME_REGEX = re.compile(
    r"(^\.[A-Za-z0-9]{6,}$)|"
    r"([A-Za-z0-9]{12,})|"
    r"(miner|payload|reverse|shell|backdoor|malware|exploit)",
    re.IGNORECASE
)

TMP_PATH_REGEX = re.compile(r"(/tmp/[^\s]+)")


def is_executable(file_path):
    try:
        file_stat = file_path.stat()
        return bool(file_stat.st_mode & stat.S_IXUSR)
    except OSError:
        return False


def has_shebang(file_path):
    try:
        with file_path.open("rb") as file:
            return file.read(2) == b"#!"
    except OSError:
        return False


def is_suspicious_tmp_file(file_path):
    reasons = []

    if not file_path.is_file():
        return reasons

    if is_executable(file_path):
        reasons.append("archivo_ejecutable_en_tmp")

    if file_path.suffix.lower() in SUSPICIOUS_EXTENSIONS and is_executable(file_path):
        reasons.append(f"script_o_binario_ejecutable_extension={file_path.suffix}")

    if has_shebang(file_path) and is_executable(file_path):
        reasons.append("script_con_shebang_ejecutable")

    if SUSPICIOUS_NAME_REGEX.search(file_path.name):
        reasons.append("nombre_sospechoso")

    return reasons


def detect_suspicious_tmp_files(tmp_dir="/tmp", recursive=True):
    tmp_path = Path(tmp_dir)
    alarms = []

    if not tmp_path.exists():
        return alarms

    if recursive:
        iterator = tmp_path.rglob("*")
    else:
        iterator = tmp_path.iterdir()

    for path in iterator:
        try:
            reasons = is_suspicious_tmp_file(path)
        except OSError:
            continue

        if not reasons:
            continue

        alarms.append({
            "tipo_alarma": "ARCHIVO_TMP_SOSPECHOSO",
            "ip_origen": "N/A",
            "modulo": "tmp_monitor",
            "archivo": str(path),
            "descripcion": f"Archivo sospechoso en /tmp: {path}. Motivos: {', '.join(reasons)}",
            "motivos": reasons
        })

    return alarms


def read_ps_output(sample_ps=None):
    if sample_ps:
        with open(sample_ps, "r", encoding="utf-8", errors="ignore") as file:
            return file.read()

    result = subprocess.run(
        ["ps", "-eo", "pid,user,comm,args", "--no-headers"],
        capture_output=True,
        text=True,
        check=True
    )

    return result.stdout


def detect_tmp_processes(sample_ps=None):
    output = read_ps_output(sample_ps)
    alarms = []

    for line in output.splitlines():
        clean_line = line.strip()

        if not clean_line:
            continue

        parts = clean_line.split(maxsplit=3)

        if len(parts) < 4:
            continue

        pid, user, comm, args = parts
        tmp_match = TMP_PATH_REGEX.search(args)

        if not tmp_match:
            continue

        alarms.append({
            "tipo_alarma": "PROCESO_TMP_SOSPECHOSO",
            "ip_origen": "N/A",
            "modulo": "tmp_monitor",
            "pid": pid,
            "usuario": user,
            "proceso": comm,
            "archivo": tmp_match.group(1),
            "descripcion": f"Proceso ejecutandose desde /tmp: PID {pid}, usuario {user}, comando {args}",
            "raw": clean_line
        })

    return alarms


def detect_tmp_threats(tmp_dir="/tmp", recursive=True, sample_ps=None):
    alarms = []
    alarms.extend(detect_suspicious_tmp_files(tmp_dir, recursive))
    alarms.extend(detect_tmp_processes(sample_ps))
    return alarms


def notify_alarm(alarm):
    log_alarm(alarm["tipo_alarma"], alarm["ip_origen"])

    send_admin_email(
        f"[HIPS ALERTA] {alarm['tipo_alarma']}",
        (
            f"Modulo: {alarm['modulo']}\n"
            f"Detalle: {alarm['descripcion']}\n"
            f"Archivo: {alarm.get('archivo', 'N/A')}"
        )
    )


def apply_prevention(alarm, dry_run=True, quarantine_dir="/var/lib/hips/quarantine"):
    if alarm["tipo_alarma"] == "ARCHIVO_TMP_SOSPECHOSO":
        return quarantine_file(
            alarm["archivo"],
            tipo_alarma=alarm["tipo_alarma"],
            quarantine_dir=quarantine_dir,
            dry_run=dry_run
        )

    if alarm["tipo_alarma"] == "PROCESO_TMP_SOSPECHOSO":
        process_result = terminate_process(
            alarm["pid"],
            alarm["proceso"],
            alarm["usuario"],
            tipo_alarma=alarm["tipo_alarma"],
            dry_run=dry_run
        )

        file_result = quarantine_file(
            alarm["archivo"],
            tipo_alarma=alarm["tipo_alarma"],
            quarantine_dir=quarantine_dir,
            dry_run=dry_run
        )

        return {
            "process": process_result,
            "file": file_result
        }

    return {
        "prevented": False,
        "reason": "No hay prevencion configurada"
    }


def main():
    parser = argparse.ArgumentParser(
        description="Modulo HIPS de monitoreo del directorio /tmp"
    )

    parser.add_argument("--tmp-dir", default="/tmp")
    parser.add_argument("--no-recursive", action="store_true")
    parser.add_argument("--sample-ps", help="Archivo con salida simulada de ps")
    parser.add_argument("--quarantine-dir", default="/var/lib/hips/quarantine")
    parser.add_argument("--prevent", action="store_true")
    parser.add_argument("--real-prevent", action="store_true")

    args = parser.parse_args()

    alarms = detect_tmp_threats(
        tmp_dir=args.tmp_dir,
        recursive=not args.no_recursive,
        sample_ps=args.sample_ps
    )

    for alarm in alarms:
        notify_alarm(alarm)

        if args.prevent:
            result = apply_prevention(
                alarm,
                dry_run=not args.real_prevent,
                quarantine_dir=args.quarantine_dir
            )
            print(f"Prevencion: {result}")

        print(alarm)

    if not alarms:
        print("No se detectaron archivos ni procesos sospechosos en /tmp.")


if __name__ == "__main__":
    main()
