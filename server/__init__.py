"""
Servidor SOC - Paquete principal.

Modulos disponibles:
    config:   Configuracion del servidor
    db:       Gestion de base de datos
    alerts:   Envio de alertas
    server:   Aplicacion Flask principal
"""
from .config import (
    AGENT_API_KEY, RATE_LIMIT_RPM, SERVER_PORT,
    TELEGRAM_TOKEN, TELEGRAM_CHAT_ID, ALERT_THRESHOLD_RISK,
    MAX_FIELD_LENGTH, get_server_info, validate_server_config
)

__all__ = [
    "AGENT_API_KEY", "RATE_LIMIT_RPM", "SERVER_PORT",
    "TELEGRAM_TOKEN", "TELEGRAM_CHAT_ID", "ALERT_THRESHOLD_RISK",
    "MAX_FIELD_LENGTH", "get_server_info", "validate_server_config",
]
