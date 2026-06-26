import argparse
import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path

from alerts.logger import current_timestamp, log_alarm, log_prevention
from alerts.mailer import send_admin_email


DEFAULT_BASELINE_FILE = Path(
    os.getenv(
        "HIPS_FILE_INTEGRITY_BASELINE",
        "/var/lib/hips/baselines/file_integrity_baseline.json"
    )
)

DEFAULT_MONITORED_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/bin/bash",
    "/usr/bin/sudo",
    "/usr/bin/ssh",
    "/usr/sbin/sshd",
]


def calculate_sha256(file_path):
    digest = hashlib.sha256()

    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def get_file_metadata(file_path):
    path = Path(file_path)

    if not path.exists():
        return {
            "path": str(path),
            "exists": False,
            "sha256": None,
            "size": None,
            "mode": None,
            "uid": None,
            "gid": None,
            "mtime": None,
        }

    file_stat = path.stat()

    return {
        "path": str(path),
        "exists": True,
        "sha256": calculate_sha256(path),
        "size": file_stat.st_size,
        "mode": oct(stat.S_IMODE(file_stat.st_mode)),
        "uid": file_stat.st_uid,
        "gid": file_stat.st_gid,
        "mtime": int(file_stat.st_mtime),
    }


def ensure_baseline_parent(baseline_file):
    baseline_path = Path(baseline_file)
    baseline_path.parent.mkdir(parents=True, exist_ok=True)


def save_baseline(paths, baseline_file):
    baseline_path = Path(baseline_file)
    ensure_baseline_parent(baseline_path)

    baseline = {
        "created_at": current_timestamp(),
        "files": {}
    }

    for file_path in paths:
        metadata = get_file_metadata(file_path)
        baseline["files"][str(file_path)] = metadata

    temporary_file = baseline_path.with_suffix(".tmp")

    with temporary_file.open("w", encoding="utf-8") as file:
        json.dump(baseline, file, indent=2, sort_keys=True)

    temporary_file.replace(baseline_path)
    os.chmod(baseline_path, 0o600)

    return baseline


def load_baseline(baseline_file):
    baseline_path = Path(baseline_file)

    if not baseline_path.exists():
        raise FileNotFoundError(
            f"No existe baseline: {baseline_path}. "
            "Primero ejecute el modulo con --init-baseline."
        )

    with baseline_path.open("r", encoding="utf-8") as file:
        return json.load(file)


def classify_alarm(file_path):
    normalized_path = str(file_path)

    if normalized_path == "/etc/passwd":
        return "MODIFICACION_PASSWD"

    if normalized_path == "/etc/shadow":
        return "MODIFICACION_SHADOW"

    if normalized_path.startswith(("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/")):
        return "BINARIO_SISTEMA_MODIFICADO"

    return "ARCHIVO_PROTEGIDO_MODIFICADO"


def compare_metadata(expected, current):
    reasons = []

    if expected["exists"] and not current["exists"]:
        reasons.append("archivo_eliminado")
        return reasons

    if not expected["exists"] and current["exists"]:
        reasons.append("archivo_creado_luego_del_baseline")
        return reasons

    if not expected["exists"] and not current["exists"]:
        return reasons

    if expected["sha256"] != current["sha256"]:
        reasons.append("contenido_modificado")

    if expected["mode"] != current["mode"]:
        reasons.append(
            f"permisos_modificados baseline={expected['mode']} actual={current['mode']}"
        )

    if expected["uid"] != current["uid"]:
        reasons.append(
            f"uid_modificado baseline={expected['uid']} actual={current['uid']}"
        )

    if expected["gid"] != current["gid"]:
        reasons.append(
            f"gid_modificado baseline={expected['gid']} actual={current['gid']}"
        )

    return reasons


def detect_file_integrity(baseline_file):
    baseline = load_baseline(baseline_file)
    alarms = []

    for file_path, expected_metadata in baseline["files"].items():
        current_metadata = get_file_metadata(file_path)
        reasons = compare_metadata(expected_metadata, current_metadata)

        if not reasons:
            continue

        alarm = {
            "tipo_alarma": classify_alarm(file_path),
            "ip_origen": "N/A",
            "modulo": "file_integrity",
            "archivo": file_path,
            "descripcion": f"{file_path}: {', '.join(reasons)}",
            "baseline": expected_metadata,
            "actual": current_metadata,
            "motivos": reasons,
        }

        alarms.append(alarm)

    return alarms


def apply_file_integrity_prevention(alarm, dry_run=True, lock_files=False):
    file_path = Path(alarm["archivo"])
    expected = alarm["baseline"]

    action = "file_integrity_prevention"

    if not file_path.exists():
        result = "No se pudo aplicar prevencion: el archivo ya no existe"

        log_prevention(alarm["tipo_alarma"], action, result, alarm["ip_origen"])
        send_admin_email(
            f"[HIPS PREVENCION] {alarm['tipo_alarma']}",
            f"Modulo: file_integrity\nArchivo: {file_path}\nResultado: {result}"
        )

        return {
            "prevented": False,
            "file": str(file_path),
            "reason": result,
        }

    if dry_run:
        result = (
            "DRY RUN: se restaurarian permisos/propietario segun baseline. "
            "Si se usa --real-prevent --lock-files, tambien se aplicaria chattr +i."
        )

        log_prevention(alarm["tipo_alarma"], action, result, alarm["ip_origen"])
        send_admin_email(
            f"[HIPS PREVENCION] {alarm['tipo_alarma']}",
            f"Modulo: file_integrity\nArchivo: {file_path}\nResultado: {result}"
        )

        return {
            "prevented": False,
            "file": str(file_path),
            "reason": result,
        }

    restored_actions = []

    if expected.get("uid") is not None and expected.get("gid") is not None:
        os.chown(file_path, int(expected["uid"]), int(expected["gid"]))
        restored_actions.append(
            f"owner restaurado a {expected['uid']}:{expected['gid']}"
        )

    if expected.get("mode") is not None:
        os.chmod(file_path, int(expected["mode"], 8))
        restored_actions.append(f"permisos restaurados a {expected['mode']}")

    if lock_files:
        subprocess.run(["chattr", "+i", str(file_path)], check=True)
        restored_actions.append("archivo bloqueado con chattr +i")

    if restored_actions:
        result = "; ".join(restored_actions)
    else:
        result = "No habia metadata para restaurar"

    if "contenido_modificado" in alarm["motivos"]:
        result += (
            "; contenido modificado detectado. "
            "No se restaura contenido automaticamente desde hashes; requiere revision del administrador."
        )

    log_prevention(alarm["tipo_alarma"], action, result, alarm["ip_origen"])
    send_admin_email(
        f"[HIPS PREVENCION] {alarm['tipo_alarma']}",
        f"Modulo: file_integrity\nArchivo: {file_path}\nResultado: {result}"
    )

    return {
        "prevented": True,
        "file": str(file_path),
        "reason": result,
    }


def read_paths_from_file(paths_file):
    paths = []

    with open(paths_file, "r", encoding="utf-8") as file:
        for line in file:
            clean_line = line.strip()

            if clean_line and not clean_line.startswith("#"):
                paths.append(clean_line)

    return paths


def resolve_paths(args):
    paths = []

    if args.paths:
        paths.extend(args.paths)

    if args.paths_file:
        paths.extend(read_paths_from_file(args.paths_file))

    if not paths:
        paths = DEFAULT_MONITORED_PATHS

    return list(dict.fromkeys(paths))


def main():
    parser = argparse.ArgumentParser(
        description="Modulo HIPS de integridad de archivos"
    )

    parser.add_argument(
        "--baseline",
        default=str(DEFAULT_BASELINE_FILE),
        help="Ruta del archivo baseline"
    )

    parser.add_argument(
        "--paths",
        nargs="*",
        help="Archivos especificos a monitorear"
    )

    parser.add_argument(
        "--paths-file",
        help="Archivo con lista de rutas a monitorear"
    )

    parser.add_argument(
        "--init-baseline",
        action="store_true",
        help="Genera el baseline inicial"
    )

    parser.add_argument(
        "--prevent",
        action="store_true",
        help="Ejecuta accion de prevencion"
    )

    parser.add_argument(
        "--real-prevent",
        action="store_true",
        help="Aplica cambios reales de prevencion"
    )

    parser.add_argument(
        "--lock-files",
        action="store_true",
        help="Bloquea archivos modificados con chattr +i en modo real"
    )

    args = parser.parse_args()

    baseline_file = Path(args.baseline)
    paths = resolve_paths(args)

    if args.init_baseline:
        baseline = save_baseline(paths, baseline_file)
        print(f"Baseline creado: {baseline_file}")
        print(f"Archivos registrados: {len(baseline['files'])}")
        return

    alarms = detect_file_integrity(baseline_file)

    for alarm in alarms:
        log_alarm(alarm["tipo_alarma"], alarm["ip_origen"])

        send_admin_email(
            f"[HIPS ALERTA] {alarm['tipo_alarma']}",
            (
                f"Modulo: {alarm['modulo']}\n"
                f"Archivo: {alarm['archivo']}\n"
                f"Detalle: {alarm['descripcion']}"
            )
        )

        if args.prevent:
            result = apply_file_integrity_prevention(
                alarm,
                dry_run=not args.real_prevent,
                lock_files=args.lock_files
            )
            print(f"Prevencion: {result}")

        print(alarm)

    if not alarms:
        print("No se detectaron modificaciones en archivos protegidos.")


if __name__ == "__main__":
    main()
