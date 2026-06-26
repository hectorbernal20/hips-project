import secrets
import string
import subprocess
import pwd

from alerts.logger import log_prevention
from alerts.mailer import send_admin_email


PROTECTED_USERS = {
    "root",
    "hector",
    "postgres"
}


def user_exists(username):
    try:
        pwd.getpwnam(username)
        return True
    except KeyError:
        return False


def generate_password(length=18):
    alphabet = string.ascii_letters + string.digits + "!@#$%_-"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def lock_user(username, tipo_alarma="USUARIO_SOSPECHOSO", dry_run=True):
    if username in PROTECTED_USERS:
        resultado = f"Usuario protegido, no se bloquea: {username}"

        log_prevention(tipo_alarma, "lock_user", resultado, "N/A")
        send_admin_email(
            f"[HIPS PREVENCION] {tipo_alarma}",
            resultado
        )

        return {
            "locked": False,
            "user": username,
            "reason": resultado
        }

    if not user_exists(username):
        resultado = f"Usuario no existe en el sistema: {username}"

        log_prevention(tipo_alarma, "lock_user", resultado, "N/A")
        send_admin_email(
            f"[HIPS PREVENCION] {tipo_alarma}",
            resultado
        )

        return {
            "locked": False,
            "user": username,
            "reason": resultado
        }

    if dry_run:
        resultado = f"DRY RUN: se bloquearia el usuario {username}"
    else:
        subprocess.run(["usermod", "-L", username], check=True)
        resultado = f"Usuario bloqueado: {username}"

    log_prevention(tipo_alarma, "lock_user", resultado, "N/A")
    send_admin_email(
        f"[HIPS PREVENCION] {tipo_alarma}",
        resultado
    )

    return {
        "locked": not dry_run,
        "user": username,
        "reason": resultado
    }


def change_user_password(username, tipo_alarma="USUARIO_SOSPECHOSO", dry_run=True):
    if username in PROTECTED_USERS:
        resultado = f"Usuario protegido, no se cambia contrasena: {username}"

        log_prevention(tipo_alarma, "change_user_password", resultado, "N/A")
        send_admin_email(
            f"[HIPS PREVENCION] {tipo_alarma}",
            resultado
        )

        return {
            "changed": False,
            "user": username,
            "reason": resultado
        }

    if not user_exists(username):
        resultado = f"Usuario no existe en el sistema: {username}"

        log_prevention(tipo_alarma, "change_user_password", resultado, "N/A")
        send_admin_email(
            f"[HIPS PREVENCION] {tipo_alarma}",
            resultado
        )

        return {
            "changed": False,
            "user": username,
            "reason": resultado
        }

    new_password = generate_password()

    if dry_run:
        resultado = f"DRY RUN: se cambiaria la contrasena del usuario {username}"
    else:
        subprocess.run(
            ["chpasswd"],
            input=f"{username}:{new_password}",
            text=True,
            check=True
        )
        resultado = f"Contrasena cambiada para usuario: {username}"

    log_prevention(tipo_alarma, "change_user_password", resultado, "N/A")
    send_admin_email(
        f"[HIPS PREVENCION] {tipo_alarma}",
        resultado
    )

    return {
        "changed": not dry_run,
        "user": username,
        "reason": resultado
    }


def force_logout_user(username, tipo_alarma="USUARIO_SOSPECHOSO", dry_run=True):
    if username in PROTECTED_USERS:
        resultado = f"Usuario protegido, no se fuerza logout: {username}"

        log_prevention(tipo_alarma, "force_logout_user", resultado, "N/A")
        send_admin_email(
            f"[HIPS PREVENCION] {tipo_alarma}",
            resultado
        )

        return {
            "logged_out": False,
            "user": username,
            "reason": resultado
        }

    if dry_run:
        resultado = f"DRY RUN: se cerrarian sesiones del usuario {username}"
    else:
        subprocess.run(["pkill", "-KILL", "-u", username], check=False)
        resultado = f"Sesiones cerradas para usuario: {username}"

    log_prevention(tipo_alarma, "force_logout_user", resultado, "N/A")
    send_admin_email(
        f"[HIPS PREVENCION] {tipo_alarma}",
        resultado
    )

    return {
        "logged_out": not dry_run,
        "user": username,
        "reason": resultado
    }
