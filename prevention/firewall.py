import subprocess


DEFAULT_WHITELIST = {
    "127.0.0.1",
    "localhost",
    "192.168.56.1"
}


def block_ip(ip_address, reason="HIPS prevention", dry_run=True, whitelist=None):
    whitelist = whitelist or DEFAULT_WHITELIST

    if ip_address in whitelist:
        return {
            "blocked": False,
            "ip": ip_address,
            "reason": "IP en whitelist, no se bloquea",
            "command": None
        }

    command = [
        "firewall-cmd",
        "--permanent",
        "--add-rich-rule",
        f"rule family='ipv4' source address='{ip_address}' reject"
    ]

    if dry_run:
        return {
            "blocked": False,
            "ip": ip_address,
            "reason": f"DRY RUN: se bloquearia por {reason}",
            "command": " ".join(command)
        }

    subprocess.run(command, check=True)
    subprocess.run(["firewall-cmd", "--reload"], check=True)

    return {
        "blocked": True,
        "ip": ip_address,
        "reason": reason,
        "command": " ".join(command)
    }
