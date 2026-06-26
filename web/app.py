from pathlib import Path
import os

from dotenv import load_dotenv
from flask import Flask, redirect, render_template, request, url_for, flash
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash


load_dotenv()

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
    alarmas = read_log_file("alarmas.log")
    prevenciones = read_log_file("prevencion.log")
    emails = read_log_file("emails.log")

    return render_template(
        "dashboard.html",
        alarmas=alarmas,
        prevenciones=prevenciones,
        emails=emails
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
