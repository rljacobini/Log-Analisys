"""
Configuracion del Servidor SOC.

Este archivo contiene toda la configuracion necesaria para que el servidor
de procesamiento de logs funcione correctamente.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.absolute()

load_dotenv(BASE_DIR / ".env")

PROJECT_ROOT = BASE_DIR.parent

SERVER_HOST = os.environ.get("SERVER_HOST", "0.0.0.0")
SERVER_PORT = int(os.environ.get("SERVER_PORT", 5000))

ENABLE_SSL = os.environ.get("ENABLE_SSL", "true").lower() == "true"
_SSL_CERT = os.environ.get("SSL_CERT_FILE", "server.crt")
_SSL_KEY = os.environ.get("SSL_KEY_FILE", "server.key")
SSL_CERT_FILE = str(BASE_DIR / _SSL_CERT) if not os.path.isabs(_SSL_CERT) else _SSL_CERT
SSL_KEY_FILE = str(BASE_DIR / _SSL_KEY) if not os.path.isabs(_SSL_KEY) else _SSL_KEY

MAX_FIELD_LENGTH = {
    'ip': 45,
    'agent_id': 100,
    'attack_type': 50,
    'source': 50,
    'target_host': 100,
    'target_service': 50,
    'hostname': 100,
}
SERVER_URL = f"https://{SERVER_HOST}:{SERVER_PORT}" if ENABLE_SSL else f"http://{SERVER_HOST}:{SERVER_PORT}"

AGENT_API_KEY = os.environ.get("AGENT_API_KEY")

RATE_LIMIT_RPM = int(os.environ.get("RATE_LIMIT_RPM", 60))

DB_PATH = os.environ.get("DB_PATH", str(BASE_DIR / "database.db"))

TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")

ALERT_THRESHOLD_RISK = int(os.environ.get("ALERT_THRESHOLD_RISK", 10))

MAX_CONCURRENT_REQUESTS = int(os.environ.get("MAX_CONCURRENT_REQUESTS", 50))
MAX_REQUEST_SIZE_KB = int(os.environ.get("MAX_REQUEST_SIZE_KB", 64))

EVENT_QUEUE_SIZE = int(os.environ.get("EVENT_QUEUE_SIZE", 1000))
EVENT_BATCH_SIZE = int(os.environ.get("EVENT_BATCH_SIZE", 50))
EVENT_BATCH_TIMEOUT = int(os.environ.get("EVENT_BATCH_TIMEOUT", 5))

CIRCUIT_BREAKER_FAILURE_THRESHOLD = int(os.environ.get("CIRCUIT_BREAKER_FAILURE_THRESHOLD", 5))
CIRCUIT_BREAKER_RECOVERY_TIMEOUT = int(os.environ.get("CIRCUIT_BREAKER_RECOVERY_TIMEOUT", 60))

RATE_LIMIT_BURST = int(os.environ.get("RATE_LIMIT_BURST", 20))

FLASK_DEBUG = os.environ.get("FLASK_DEBUG", "false").lower() == "true"

DASHBOARD_AUTH_ENABLED = os.environ.get("DASHBOARD_AUTH_ENABLED", "true").lower() == "true"
DASHBOARD_USERNAME = os.environ.get("DASHBOARD_USERNAME", "admin")
DASHBOARD_PASSWORD_HASH = os.environ.get("DASHBOARD_PASSWORD_HASH")
DASHBOARD_API_KEY = os.environ.get("DASHBOARD_API_KEY")
DASHBOARD_API_SECRET = os.environ.get("DASHBOARD_API_SECRET", "")

AGENT_API_SECRET = os.environ.get("AGENT_API_SECRET", "")
NONCE_TTL_SECONDS = int(os.environ.get("NONCE_TTL_SECONDS", "300"))

RATE_LIMIT_PER_MINUTE = int(os.environ.get("RATE_LIMIT_PER_MINUTE", 100))

# =============================================================================
# DEDUPLICACION Y LATE EVENTS
# =============================================================================

# Ventana de deduplicacion en minutos (para evitar duplicados)
# Un evento se considera duplicado si ya existe dentro de esta ventana
DEDUP_WINDOW_MINUTES = int(os.environ.get("DEDUP_WINDOW_MINUTES", 60))

# Maximo tiempo en horas para aceptar eventos historicos
# Eventos con timestamp mayor a esto seran ignorados
MAX_EVENT_AGE_HOURS = int(os.environ.get("MAX_EVENT_AGE_HOURS", 24))

# Habilitar re-correlacion periodica (para actualizar threat_intel)
ENABLE_RECORRELATION = os.environ.get("ENABLE_RECORRELATION", "true").lower() == "true"

# Intervalo de re-correlacion en horas
RECORRELATION_INTERVAL_HOURS = int(os.environ.get("RECORRELATION_INTERVAL_HOURS", 24))


def get_server_info():
    """Retorna informacion del servidor."""
    return {
        "server_url": SERVER_URL,
        "db_path": DB_PATH,
        "rate_limit_rpm": RATE_LIMIT_RPM,
        "rate_limit_burst": RATE_LIMIT_BURST,
        "max_concurrent_requests": MAX_CONCURRENT_REQUESTS,
        "max_request_size_kb": MAX_REQUEST_SIZE_KB,
        "event_queue_size": EVENT_QUEUE_SIZE,
        "event_batch_size": EVENT_BATCH_SIZE,
        "circuit_breaker_threshold": CIRCUIT_BREAKER_FAILURE_THRESHOLD,
        "circuit_breaker_recovery_timeout": CIRCUIT_BREAKER_RECOVERY_TIMEOUT,
        "alert_threshold": ALERT_THRESHOLD_RISK,
        "telegram_configured": bool(TELEGRAM_TOKEN and TELEGRAM_CHAT_ID),
    }


def validate_server_config():
    """Valida la configuracion del servidor."""
    errors = []

    if not AGENT_API_KEY:
        errors.append("AGENT_API_KEY debe ser configurada con un valor seguro")

    if not os.path.exists(os.path.dirname(DB_PATH)):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

    return errors


if __name__ == "__main__":
    print("Configuracion del Servidor SOC")
    print("=" * 50)
    for key, value in get_server_info().items():
        print(f"  {key}: {value}")
    print("=" * 50)

    errors = validate_server_config()
    if errors:
        print("ADVERTENCIAS:")
        for e in errors:
            print(f"  - {e}")
    else:
        print("Configuracion valida!")
