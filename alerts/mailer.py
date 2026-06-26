import os
import smtplib
from email.message import EmailMessage
from pathlib import Path
from datetime import datetime


LOG_DIR = Path(os.getenv("HIPS_LOG_DIR", "/var/log/hips"))


def send_admin_email(subject, body):
    """
    Envía email al administrador.
    Si HIPS_EMAIL_DRY_RUN=true, registra el email en /var/log/hips/emails.log.
    """
    dry_run = os.getenv("HIPS_EMAIL_DRY_RUN", "true").lower() == "true"
    admin_email = os.getenv("HIPS_ALERT_EMAIL", "admin@example.com")

    if dry_run:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        line = (
            f"{datetime.now().strftime('%d/%m/%Y %H:%M:%S')} :: "
            f"TO={admin_email} :: SUBJECT={subject} :: BODY={body}\n"
        )
        with (LOG_DIR / "emails.log").open("a", encoding="utf-8") as file:
            file.write(line)
        return {"sent": False, "dry_run": True, "to": admin_email}

    smtp_host = os.getenv("HIPS_SMTP_HOST", "localhost")
    smtp_port = int(os.getenv("HIPS_SMTP_PORT", "25"))
    smtp_user = os.getenv("HIPS_SMTP_USER")
    smtp_password = os.getenv("HIPS_SMTP_PASSWORD")
    smtp_from = os.getenv("HIPS_SMTP_FROM", "hips@localhost")

    message = EmailMessage()
    message["From"] = smtp_from
    message["To"] = admin_email
    message["Subject"] = subject
    message.set_content(body)

    with smtplib.SMTP(smtp_host, smtp_port) as server:
        if smtp_user and smtp_password:
            server.starttls()
            server.login(smtp_user, smtp_password)
        server.send_message(message)

    return {"sent": True, "dry_run": False, "to": admin_email}
