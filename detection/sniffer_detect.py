import argparse
import re
import subprocess
from pathlib import Path

from alerts.logger import log_alarm
from alerts.mailer import send_admin_email
from prevention.sniffer_actions import kill_process, disable_promiscuous_mode


SNIFFER_NAMES = {
    "tcpdump",
    "wireshark",
    "tshark",
    "dumpcap",
    "ethereal",
    "ettercap",
    "dsniff",
    "ngrep"
}


PS_REGEX = re.compile(
    r"^\s*(?P<pid>\d+)\s+(?P<comm>\S+)\s+(?P<args>.*)$"
)


IP_LINK_HEADER_REGEX = re.compile(
    r"^\d+:\s+(?P<iface>[^:]+):\s+<(?P<flags>[^>]*)>"
)


def run_command(command):
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=True
    )

    return result.stdout


def read_text_file(file_path):
    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
        return file.read()


def get_ps_output(sample_ps=None):
    if sample_ps:
        return read_text_file(sample_ps)

    return run_command(["ps", "-eo", "pid,comm,args", "--no-headers"])


def get_ip_link_output(sample_ip_link=None):
    if sample_ip_link:
        return read_text_file(sample_ip_link)

    return run_command(["ip", "-details", "link", "show"])


def detect_sniffer_processes(sample_ps=None):
    output = get_ps_output(sample_ps)
    detections = []

    for line in output.splitlines():
        match = PS_REGEX.match(line)

        if not match:
            continue

        pid = match.group("pid")
        comm = match.group("comm")
        args = match.group("args")
        process_name = Path(comm).name.lower()
        args_lower = args.lower()

        if process_name in SNIFFER_NAMES or any(tool in args_lower for tool in SNIFFER_NAMES):
            detections.append({
                "tipo_alarma": "SNIFFER_DETECTADO",
                "ip_origen": "N/A",
                "modulo": "sniffer_detect",
                "pid": pid,
                "proceso": comm,
                "descripcion": f"Herramienta de captura detectada: {comm} PID {pid}",
                "raw": line.strip()
            })

    return detections


def detect_promiscuous_interfaces(sample_ip_link=None):
    output = get_ip_link_output(sample_ip_link)
    detections = []

    for line in output.splitlines():
        match = IP_LINK_HEADER_REGEX.match(line.strip())

        if not match:
            continue

        interface = match.group("iface").split("@")[0]
        flags = {flag.strip().upper() for flag in match.group("flags").split(",")}

        if "PROMISC" in flags:
            detections.append({
                "tipo_alarma": "MODO_PROMISCUO_DETECTADO",
                "ip_origen": "N/A",
                "modulo": "sniffer_detect",
                "interfaz": interface,
                "descripcion": f"Interfaz en modo promiscuo: {interface}",
                "raw": line.strip()
            })

    return detections


def detect_sniffers(sample_ps=None, sample_ip_link=None):
    alarms = []
    alarms.extend(detect_sniffer_processes(sample_ps))
    alarms.extend(detect_promiscuous_interfaces(sample_ip_link))
    return alarms


def notify_alarm(alarm):
    log_alarm(alarm["tipo_alarma"], alarm["ip_origen"])

    send_admin_email(
        f"[HIPS ALERTA] {alarm['tipo_alarma']}",
        (
            f"Modulo: {alarm['modulo']}\n"
            f"Detalle: {alarm['descripcion']}\n"
            f"Raw: {alarm.get('raw', 'N/A')}"
        )
    )


def main():
    parser = argparse.ArgumentParser(
        description="Modulo HIPS de deteccion de sniffers y modo promiscuo"
    )

    parser.add_argument(
        "--sample-ps",
        help="Archivo de prueba con salida simulada de ps"
    )

    parser.add_argument(
        "--sample-ip-link",
        help="Archivo de prueba con salida simulada de ip -details link show"
    )

    parser.add_argument(
        "--prevent",
        action="store_true",
        help="Ejecuta acciones de prevencion"
    )

    parser.add_argument(
        "--real-prevent",
        action="store_true",
        help="Aplica prevencion real"
    )

    parser.add_argument(
        "--disable-promisc",
        action="store_true",
        help="Desactiva modo promiscuo si se detecta"
    )

    args = parser.parse_args()

    alarms = detect_sniffers(
        sample_ps=args.sample_ps,
        sample_ip_link=args.sample_ip_link
    )

    for alarm in alarms:
        notify_alarm(alarm)

        if args.prevent:
            if alarm["tipo_alarma"] == "SNIFFER_DETECTADO":
                result = kill_process(
                    alarm["pid"],
                    alarm["proceso"],
                    tipo_alarma=alarm["tipo_alarma"],
                    dry_run=not args.real_prevent
                )
                print(f"Prevencion: {result}")

            if alarm["tipo_alarma"] == "MODO_PROMISCUO_DETECTADO" and args.disable_promisc:
                result = disable_promiscuous_mode(
                    alarm["interfaz"],
                    tipo_alarma=alarm["tipo_alarma"],
                    dry_run=not args.real_prevent
                )
                print(f"Prevencion: {result}")

        print(alarm)

    if not alarms:
        print("No se detectaron sniffers ni interfaces en modo promiscuo.")


if __name__ == "__main__":
    main()
