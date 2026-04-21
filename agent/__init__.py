"""
Agente SOC - Paquete principal.

Modulos disponibles:
    config:    Configuracion del agente
    patterns:  Patrones de deteccion de eventos
    agent:     Logica principal del agente
"""
from .config import (
    AGENT_ID, TARGET_HOST, TARGET_SERVICE, SOURCE,
    SERVER_URL, X_API_KEY, LOG_FILE, AGENT_INTERVAL,
    DETECTION_THRESHOLDS, SEND_COOLDOWN, REQUEST_TIMEOUT,
    get_agent_info, validate_agent_config
)
from .patterns import (
    AUTH_LOG_PATTERNS, IPTABLES_PATTERNS, SURICATA_PATTERNS,
    get_patterns_for_source, get_risk_weight, determine_severity
)

__all__ = [
    "AGENT_ID", "TARGET_HOST", "TARGET_SERVICE", "SOURCE",
    "SERVER_URL", "X_API_KEY", "LOG_FILE", "AGENT_INTERVAL",
    "DETECTION_THRESHOLDS", "SEND_COOLDOWN", "REQUEST_TIMEOUT",
    "get_agent_info", "validate_agent_config",
    "AUTH_LOG_PATTERNS", "IPTABLES_PATTERNS", "SURICATA_PATTERNS",
    "get_patterns_for_source", "get_risk_weight", "determine_severity",
]
