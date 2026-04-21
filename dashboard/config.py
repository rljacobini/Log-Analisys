"""
Configuracion del Dashboard SOC.

Este archivo contiene toda la configuracion necesaria para que el dashboard
funcione independientemente o conectado a un servidor SOC remoto via API.
"""
import os
import secrets
import logging
from pathlib import Path

from dotenv import load_dotenv

logger = logging.getLogger(__name__)

load_dotenv(Path(__file__).parent / ".env")

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent

DASHBOARD_HOST = os.environ.get("DASHBOARD_HOST", "0.0.0.0")
DASHBOARD_PORT = int(os.environ.get("DASHBOARD_PORT", 8000))

DASHBOARD_USERNAME = os.environ.get("DASHBOARD_USERNAME", "admin")
DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD")

raw_secret = os.environ.get("SECRET_KEY")
if not raw_secret or (isinstance(raw_secret, str) and len(raw_secret) < 32):
    SECRET_KEY = secrets.token_urlsafe(64)
    logger.warning(
        "SECRET_KEY auto-generada. "
        "Configure SECRET_KEY en .env para persistencia."
    )
else:
    SECRET_KEY = raw_secret

USE_REMOTE_API = os.environ.get("USE_REMOTE_API", "false").lower() == "true"
SOC_API_URL = os.environ.get("SOC_API_URL", "http://localhost:5000")
SOC_VERIFY_SSL = os.environ.get("SOC_VERIFY_SSL", "false").lower() == "true"

DB_PATH = os.environ.get("DB_PATH", str(PROJECT_ROOT / "server" / "database.db"))

PAGE_SIZE = int(os.environ.get("PAGE_SIZE", 50))

FLASK_DEBUG = os.environ.get("FLASK_DEBUG", "false").lower() == "true"

DASHBOARD_USE_SSL = os.environ.get("DASHBOARD_USE_SSL", "false").lower() == "true"
raw_cert = os.environ.get("DASHBOARD_CERT_FILE")
raw_key = os.environ.get("DASHBOARD_KEY_FILE")
DASHBOARD_CERT_FILE = str(BASE_DIR / raw_cert) if raw_cert and not os.path.isabs(raw_cert) else raw_cert
DASHBOARD_KEY_FILE = str(BASE_DIR / raw_key) if raw_key and not os.path.isabs(raw_key) else raw_key


def get_dashboard_info():
    """Retorna informacion del dashboard."""
    return {
        "dashboard_url": f"http://{DASHBOARD_HOST}:{DASHBOARD_PORT}",
        "db_path": DB_PATH,
        "page_size": PAGE_SIZE,
        "secret_key_configured": isinstance(raw_secret, str) and len(raw_secret) >= 32,
    }


def validate_dashboard_config():
    """Valida la configuracion del dashboard."""
    errors = []
    warnings = []

    if not DASHBOARD_PASSWORD:
        errors.append("DASHBOARD_PASSWORD debe ser configurado")

    if not raw_secret:
        warnings.append("SECRET_KEY no configurado - se genero una nueva")

    if not os.path.exists(DB_PATH):
        errors.append(f"Base de datos no encontrada: {DB_PATH}")

    return errors, warnings


if __name__ == "__main__":
    print("Configuracion del Dashboard SOC")
    print("=" * 50)
    for key, value in get_dashboard_info().items():
        print(f"  {key}: {value}")
    print("=" * 50)

    errors, warnings = validate_dashboard_config()
    if errors:
        print("ERRORES:")
        for e in errors:
            print(f"  - {e}")
    if warnings:
        print("ADVERTENCIAS:")
        for w in warnings:
            print(f"  - {w}")
    if not errors:
        print("Configuracion valida!")