from pathlib import Path
import os
import sys

from dotenv import load_dotenv
from flask import Flask, redirect, render_template, request, url_for, flash
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

load_dotenv(PROJECT_ROOT / ".env")

app = Flask(__name__)
app.secret_key = os.getenv("HIPS_SECRET_KEY", "change_me")

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


class User(UserMixin):
    def __init__(self, user_id):
        self.id = user_id


@login_manager.user_loader
def load_user(user_id):
    return User(user_id)


def read_log_file(filename, limit=50):
    log_dir = Path(os.getenv("HIPS_LOG_DIR", "/var/log/hips"))
    log_path = log_dir / filename

    if not log_path.exists():
        return []

    lines = log_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    return list(reversed(lines[-limit:]))


def db_fetch_all(query, params=None):
    if os.getenv("HIPS_DB_ENABLED", "false").lower() != "true":
        return None

    connection = None

    try:
        from db.connection import get_connection

        connection = get_connection()

        if connection is None:
            return None

        with connection:
            with connection.cursor() as cursor:
                cursor.execute(query, params or ())
                columns = [column[0] for column in cursor.description]
                return [
                    dict(zip(columns, row))
                    for row in cursor.fetchall()
                ]

    except Exception as error:
        print(f"[HIPS WEB DB WARNING] {error}", file=sys.stderr)
        return None

    finally:
        if connection is not None:
            connection.close()


def get_alarmas(limit=50):
    query = """
        SELECT
            id,
            timestamp,
            tipo_alarma,
            COALESCE(ip_origen, 'N/A') AS ip_origen,
            modulo,
            descripcion,
            resuelta
        FROM alarmas
        ORDER BY timestamp DESC, id DESC
        LIMIT %s
    """

    rows = db_fetch_all(query, (limit,))

    if rows is not None:
        return rows, "PostgreSQL"

    fallback_rows = [
        {"registro": line}
        for line in read_log_file("alarmas.log", limit)
    ]

    return fallback_rows, "Archivo de log"


def get_prevenciones(limit=50):
    query = """
        SELECT
            id,
            timestamp,
            COALESCE(tipo_alarma, 'N/A') AS tipo_alarma,
            COALESCE(ip_origen, 'N/A') AS ip_origen,
            accion,
            resultado
        FROM acciones_prevencion
        ORDER BY timestamp DESC, id DESC
        LIMIT %s
    """

    rows = db_fetch_all(query, (limit,))

    if rows is not None:
        return rows, "PostgreSQL"

    fallback_rows = [
        {"registro": line}
        for line in read_log_file("prevencion.log", limit)
    ]

    return fallback_rows, "Archivo de log"


@app.route("/")
def index():
    return redirect(url_for("dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        expected_user = os.getenv("HIPS_WEB_USERNAME", "admin")
        expected_password = os.getenv("HIPS_WEB_PASSWORD", "change_me")
        expected_hash = generate_password_hash(expected_password)

        if username == expected_user and check_password_hash(expected_hash, password):
            login_user(User(username))
            return redirect(url_for("dashboard"))

        flash("Usuario o contraseña incorrectos.")

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    alarmas, alarmas_source = get_alarmas()
    prevenciones, prevenciones_source = get_prevenciones()
    emails = read_log_file("emails.log")

    return render_template(
        "dashboard.html",
        alarmas=alarmas,
        prevenciones=prevenciones,
        emails=emails,
        alarmas_source=alarmas_source,
        prevenciones_source=prevenciones_source
    )


@app.route("/config")
@login_required
def config():
    modules = [
        "file_integrity",
        "users_monitor",
        "sniffer_detect",
        "log_analyzer",
        "mail_queue",
        "process_monitor",
        "tmp_monitor",
        "ddos_detect",
        "cron_monitor",
        "access_monitor",
    ]

    return render_template("config.html", modules=modules)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
