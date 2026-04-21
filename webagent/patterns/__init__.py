"""Patrones de deteccion para diferentes fuentes de log."""
from .web import (
    WEB_LOG_PATTERNS,
    APACHE_ACCESS_PATTERN,
    NGINX_ACCESS_PATTERN,
    parse_apache_access_log,
    parse_nginx_access_log,
    check_injection_patterns,
    get_risk_weight as web_get_risk_weight,
    extract_timestamp_from_log as web_extract_timestamp,
)

__all__ = [
    "WEB_LOG_PATTERNS",
    "APACHE_ACCESS_PATTERN",
    "NGINX_ACCESS_PATTERN",
    "web_extract_timestamp",
    "web_get_risk_weight",
    "parse_apache_access_log",
    "parse_nginx_access_log",
    "check_injection_patterns",
]
