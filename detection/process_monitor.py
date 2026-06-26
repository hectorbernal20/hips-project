import argparse
import json
import os
import re
import subprocess
from datetime import datetime
from pathlib import Path

from alerts.logger import log_alarm
from alerts.mailer import send_admin_email
from prevention.process_kill import terminate_process


DEFAULT_STATE_FILE = Path(
    os.getenv(
        "HIPS_PROCESS_STATE_FILE",
        "/var/lib/hips/process_monitor_state.json"
    )
)

PS_REGEX = re.compile(
    r"^\s*(?P<pid>\d+)\s+"
    r"(?P<user>\S+)\s+"
    r"(?P<comm>\S+)\s+"
    r"(?P<mem>\d+(?:\.\d+)?)\s+"
    r"(?P<etime>\S+)\s+"
    r"(?P<args>.*)$"
)


def now_iso():
    return datetime.now().isoformat(timespec="seconds")


def parse_iso(value):
    return datetime.fromisoformat(value)


def ensure_state_parent(state_file):
    Path(state_file).parent.mkdir(parents=True, exist_ok=True)


def load_state(state_file):
    state_path = Path(state_file)

    if not state_path.exists():
        return {}

    with state_path.open("r", encoding="utf-8") as file:
        return json.load(file)


def save_state(state_file, state):
    state_path = Path(state_file)
    ensure_state_parent(state_path)

    tmp_file = state_path.with_suffix(".tmp")

    with tmp_file.open("w", encoding="utf-8") as file:
        json.dump(state, file, indent=2, sort_keys=True)

    tmp_file.replace(state_path)
    os.chmod(state_path, 0o600)


def read_ps_output(sample_file=None):
    if sample_file:
        with open(sample_file, "r", encoding="utf-8", errors="ignore") as file:
            return file.read()

    result = subprocess.run(
        ["ps", "-eo", "pid,user,comm,%mem,etime,args", "--no-headers"],
        capture_output=True,
        text=True,
        check=True
    )

    return result.stdout


def parse_ps_output(output):
    processes = []

    for line in output.splitlines():
        match = PS_REGEX.match(line)

        if not match:
            continue

        processes.append({
            "pid": match.group("pid"),
            "user": match.group("user"),
            "comm": match.group("comm"),
            "mem_percent": float(match.group("mem")),
            "etime": match.group("etime"),
            "args": match.group("args"),
            "raw": line.strip()
        })

    return processes


def process_key(process):
    return f"{process['pid']}:{process['comm']}:{process['user']}"


def detect_high_memory_processes(
    sample_file=None,
    state_file=DEFAULT_STATE_FILE,
    memory_threshold=70.0,
    min_duration_seconds=60
):
    state = load_state(state_file)
    output = read_ps_output(sample_file)
    processes = parse_ps_output(output)

    current_time = datetime.now()
    current_time_text = now_iso()

    active_keys = set()
    alarms = []

    for process in processes:
        key = process_key(process)
        active_keys.add(key)

        if process["mem_percent"] < memory_threshold:
            continue

        if key not in state:
            state[key] = {
                "first_seen": current_time_text,
                "pid": process["pid"],
                "user": process["user"],
                "comm": process["comm"],
                "mem_percent": process["mem_percent"]
            }

        first_seen = parse_iso(state[key]["first_seen"])
        duration = int((current_time - first_seen).total_seconds())

        if duration >= min_duration_seconds:
            alarms.append({
                "tipo_alarma": "PROCESO_ALTO_CONSUMO",
                "ip_origen": "N/A",
                "modulo": "process_monitor",
                "pid": process["pid"],
                "usuario": process["user"],
                "proceso": process["comm"],
                "memoria": process["mem_percent"],
                "duracion_segundos": duration,
                "descripcion": (
                    f"Proceso {process['comm']} PID {process['pid']} "
                    f"consume {process['mem_percent']}% de memoria durante "
                    f"{duration} segundos"
                ),
                "raw": process["raw"]
            })

    cleaned_state = {
        key: value
        for key, value in state.items()
        if key in active_keys
    }

    save_state(state_file, cleaned_state)

    return alarms


def main():
    parser = argparse.ArgumentParser(
        description="Modulo HIPS de monitoreo de procesos con alto consumo"
    )

    parser.add_argument(
        "--sample-file",
        help="Archivo de prueba con salida simulada de ps"
    )

    parser.add_argument(
        "--state-file",
        default=str(DEFAULT_STATE_FILE),
        help="Archivo de estado para medir duracion"
    )

    parser.add_argument(
        "--memory-threshold",
        type=float,
        default=70.0,
        help="Porcentaje de memoria para generar sospecha"
    )

    parser.add_argument(
        "--min-duration",
        type=int,
        default=60,
        help="Segundos minimos de consumo alto antes de alertar"
    )

    parser.add_argument("--prevent", action="store_true")
    parser.add_argument("--real-prevent", action="store_true")
    parser.add_argument("--force-kill", action="store_true")

    args = parser.parse_args()

    alarms = detect_high_memory_processes(
        sample_file=args.sample_file,
        state_file=args.state_file,
        memory_threshold=args.memory_threshold,
        min_duration_seconds=args.min_duration
    )

    for alarm in alarms:
        log_alarm(alarm["tipo_alarma"], alarm["ip_origen"])

        send_admin_email(
            f"[HIPS ALERTA] {alarm['tipo_alarma']}",
            (
                f"Modulo: {alarm['modulo']}\n"
                f"Proceso: {alarm['proceso']}\n"
                f"PID: {alarm['pid']}\n"
                f"Usuario: {alarm['usuario']}\n"
                f"Memoria: {alarm['memoria']}%\n"
                f"Detalle: {alarm['descripcion']}"
            )
        )

        if args.prevent:
            result = terminate_process(
                alarm["pid"],
                alarm["proceso"],
                alarm["usuario"],
                tipo_alarma=alarm["tipo_alarma"],
                dry_run=not args.real_prevent,
                force=args.force_kill
            )
            print(f"Prevencion: {result}")

        print(alarm)

    if not alarms:
        print("No se detectaron procesos con consumo excesivo sostenido.")


if __name__ == "__main__":
    main()
