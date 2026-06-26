import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = PROJECT_ROOT / ".env"


def load_env_file():
    if not ENV_FILE.exists():
        return

    with ENV_FILE.open("r", encoding="utf-8") as file:
        for line in file:
            clean_line = line.strip()

            if not clean_line or clean_line.startswith("#"):
                continue

            if "=" not in clean_line:
                continue

            key, value = clean_line.split("=", 1)
            os.environ.setdefault(
                key.strip(),
                value.strip().strip('"').strip("'")
            )


def db_enabled():
    load_env_file()
    return os.getenv("HIPS_DB_ENABLED", "false").lower() == "true"


def get_connection():
    load_env_file()

    if not db_enabled():
        return None

    try:
        import psycopg2
    except ImportError:
        return None

    return psycopg2.connect(
        host=os.getenv("HIPS_DB_HOST", "localhost"),
        port=os.getenv("HIPS_DB_PORT", "5432"),
        dbname=os.getenv("HIPS_DB_NAME", "hips_db"),
        user=os.getenv("HIPS_DB_USER", "hips_app"),
        password=os.getenv("HIPS_DB_PASSWORD")
    )
