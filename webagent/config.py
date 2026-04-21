"""
Configuracion del Agente SOC.

Este archivo contiene toda la configuracion necesaria para que el agente
de monitoreo funcione correctamente. Los valores se pueden sobrescribir
mediante variables de entorno.

Uso:
    from agent.config import AGENT_ID, SERVER_URL, LOG_FILE
"""
import os
import socket
import platform
from pathlib import Path

from dotenv import load_dotenv

from .security import validate_log_file_path

load_dotenv(Path(__file__).parent / ".env")

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent

ALLOWED_LOG_DIRS = os.environ.get("ALLOWED_LOG_DIRS", "").split(",") if os.environ.get("ALLOWED_LOG_DIRS") else []
if not ALLOWED_LOG_DIRS:
    ALLOWED_LOG_DIRS = [str(PROJECT_ROOT / "data")]


def _get_local_ip():
    """Obtiene la IP local."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _safe_log_file_path() -> str:
    """Obtiene la ruta del archivo de log validada contra path traversal."""
    default_path = str(PROJECT_ROOT / "data" / "auth.log")
    log_file = os.environ.get(
        "LOG_FILE",
        os.environ.get("AUTH_LOG_FILE", default_path)
    )

    if not os.path.isabs(log_file):
        log_file = str(PROJECT_ROOT / log_file)

    if validate_log_file_path(log_file, ALLOWED_LOG_DIRS):
        return log_file

    return default_path


def _safe_state_dir() -> str:
    """Obtiene el directorio de estado validado."""
    state_dir = os.environ.get("STATE_DIR", None)
    if state_dir and validate_log_file_path(state_dir, [str(BASE_DIR)]):
        return state_dir
    return str(BASE_DIR)


AGENT_ID = os.environ.get("AGENT_ID", socket.gethostname())
TARGET_HOST = os.environ.get("TARGET_HOST", _get_local_ip())
TARGET_SERVICE = os.environ.get("TARGET_SERVICE", "ssh")
SOURCE = os.environ.get("SOURCE", "auth.log")
AGENT_INTERVAL = int(os.environ.get("AGENT_INTERVAL", 10))

STATE_DIR = _safe_state_dir()

SERVER_URL = os.environ.get(
    "SERVER_URL",
    os.environ.get("SERVER_ENDPOINT", "https://127.0.0.1:5000/log")
)

BATCH_URL = os.environ.get("BATCH_URL", SERVER_URL.replace("/log", "/log/batch", 1))

USE_SSL = os.environ.get("USE_SSL", "true").lower() == "true"
VERIFY_SSL = os.environ.get("VERIFY_SSL", "true").lower() == "true"

X_API_KEY = os.environ.get("X_API_KEY") or os.environ.get("AGENT_API_KEY")
X_API_KEY_SECRET = os.environ.get("X_API_KEY_SECRET", "")

LOG_FILE = _safe_log_file_path()

LOG_LEVEL = os.environ.get("AGENT_LOG_LEVEL", "INFO")

DETECTION_THRESHOLDS = {
    "brute_force_attempts": int(os.environ.get("BRUTE_FORCE_THRESHOLD", 5)),
    "brute_force_window_seconds": int(os.environ.get("BRUTE_FORCE_WINDOW", 60)),
    "risk_critical": int(os.environ.get("RISK_CRITICAL", 50)),
    "risk_high": int(os.environ.get("RISK_HIGH", 30)),
    "risk_medium": int(os.environ.get("RISK_MEDIUM", 15)),
}

SEND_COOLDOWN = {
    "default": int(os.environ.get("SEND_COOLDOWN_DEFAULT", 15)),
    "critical": int(os.environ.get("SEND_COOLDOWN_CRITICAL", 0)),
    "high": int(os.environ.get("SEND_COOLDOWN_HIGH", 5)),
}

REQUEST_TIMEOUT = int(os.environ.get("AGENT_TIMEOUT", 10))

USE_BATCH_MODE = os.environ.get("USE_BATCH_MODE", "true").lower() == "true"
BATCH_SIZE = int(os.environ.get("AGENT_BATCH_SIZE", 20))
BATCH_TIMEOUT = int(os.environ.get("AGENT_BATCH_TIMEOUT", 30))
BATCH_RETRY_QUEUE_SIZE = int(os.environ.get("BATCH_RETRY_QUEUE_SIZE", 100))
MAX_BATCH_RETRIES = int(os.environ.get("MAX_BATCH_RETRIES", 3))
INITIAL_RETRY_DELAY = int(os.environ.get("INITIAL_RETRY_DELAY", 5))
MAX_RETRY_DELAY = int(os.environ.get("MAX_RETRY_DELAY", 120))

MAX_CONSECUTIVE_FAILURES = int(os.environ.get("MAX_CONSECUTIVE_FAILURES", 10))
BACKOFF_MULTIPLIER = float(os.environ.get("BACKOFF_MULTIPLIER", 2.0))


def get_agent_info():
    """Retorna informacion del agente para registro."""
    return {
        "agent_id": AGENT_ID,
        "target_host": TARGET_HOST,
        "target_service": TARGET_SERVICE,
        "source": SOURCE,
        "log_file": LOG_FILE,
        "server_url": SERVER_URL,
        "batch_mode": USE_BATCH_MODE,
        "batch_size": BATCH_SIZE,
    }


def validate_agent_config():
    """Valida la configuracion del agente."""
    errors = []

    if not SERVER_URL:
        errors.append("SERVER_URL no configurado")
    elif not SERVER_URL.startswith(("http://", "https://")):
        errors.append(f"SERVER_URL formato invalido: {SERVER_URL}")

    if not X_API_KEY:
        errors.append("X_API_KEY debe ser configurada (o AGENT_API_KEY)")

    if not os.path.exists(LOG_FILE):
        errors.append(f"Archivo de log no encontrado: {LOG_FILE}")

    return errors


if __name__ == "__main__":
    print("Configuracion del Agente SOC")
    print("=" * 50)
    for key, value in get_agent_info().items():
        print(f"  {key}: {value}")
    print("=" * 50)

    validation_errors = validate_agent_config()
    if validation_errors:
        print("ERRORES:")
        for e in validation_errors:
            print(f"  - {e}")
    else:
        print("Configuracion valida!")
