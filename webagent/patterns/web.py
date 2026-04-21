"""
Patrones para logs de servidores web (Apache, Nginx).

Formatos soportados:
- Apache Combined Log Format
- Apache Error Log Format
- Nginx Access Log Format
- Nginx Error Log Format
"""
import re
from datetime import datetime
from typing import Optional

WEB_TIMESTAMP_PATTERN = re.compile(
    r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})'
)

WEB_TIMESTAMP_ALT = re.compile(
    r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})'
)


def extract_timestamp_from_log(line: str) -> Optional[datetime]:
    """Extrae la marca de tiempo de una linea de log web."""
    match = WEB_TIMESTAMP_PATTERN.search(line)
    if match:
        try:
            return datetime.strptime(match.group(1), "%d/%b/%Y:%H:%M:%S")
        except ValueError:
            pass

    match = WEB_TIMESTAMP_ALT.search(line)
    if match:
        try:
            return datetime.fromisoformat(match.group(1))
        except ValueError:
            pass

    return None


WEB_LOG_PATTERNS = {
    "sqli_attempt": {
        "pattern": re.compile(
            r'(union|select|insert|update|delete|drop|exec|execute|script|--|;|@@version)',
            re.IGNORECASE
        ),
        "type": "sqli_attempt",
        "risk": 35,
        "description": "SQL Injection attempt",
    },
    "xss_attempt": {
        "pattern": re.compile(
            r'(<script|javascript:|onerror=|onload=|alert\(|<img|<svg|<iframe)',
            re.IGNORECASE
        ),
        "type": "xss_attempt",
        "risk": 30,
        "description": "Cross-Site Scripting attempt",
    },
    "path_traversal": {
        "pattern": re.compile(
            r'(\.\./|\.\.\\|%2e%2e|/etc/passwd|/etc/shadow|c:\\windows|c:\\boot)',
            re.IGNORECASE
        ),
        "type": "path_traversal",
        "risk": 40,
        "description": "Path traversal attempt",
    },
    "command_injection": {
        "pattern": re.compile(
            r'([;&|`$]|\\|\\n|\\r)',
            re.IGNORECASE
        ),
        "type": "command_injection",
        "risk": 45,
        "description": "Command injection attempt",
    },
    "scanner_detection": {
        "pattern": re.compile(
            r'(nmap|sqlmap|nikto|gobuster|dirb|wfuzz|burp|metasploit|acunetix| Nessus)',
            re.IGNORECASE
        ),
        "type": "scanner_detection",
        "risk": 25,
        "description": "Security scanner detected",
    },
    "http_flood": {
        "pattern": re.compile(r'^([\d.]+)\s+-\s+\S+\s+\[\d{2}/\w{3}'),
        "type": "http_flood",
        "risk": 20,
        "description": "Possible HTTP flood",
    },
    "suspicious_user_agent": {
        "pattern": re.compile(
            r'(python-requests|curl|wget|java|okhttp|go-http|axios|fetch|scrapy|bot|crawler)',
            re.IGNORECASE
        ),
        "type": "suspicious_user_agent",
        "risk": 5,
        "description": "Suspicious user agent",
    },
    "404_enumeration": {
        "pattern": re.compile(r'"(GET|POST)\s+(\S+)\s+HTTP/[\d.]+\s+404'),
        "type": "404_enumeration",
        "risk": 10,
        "description": "404 enumeration attempt",
    },
    "error_500": {
        "pattern": re.compile(r'HTTP/[\d.]+\s+500'),
        "type": "error_500",
        "risk": 15,
        "description": "Server error 500",
    },
    "error_403": {
        "pattern": re.compile(r'HTTP/[\d.]+\s+403'),
        "type": "error_403",
        "risk": 10,
        "description": "Forbidden access attempt",
    },
    "file_upload_attempt": {
        "pattern": re.compile(
            r'(upload|savefile|attach|\.php|\.asp|\.jsp|\.exe|\.sh|\.pwn)',
            re.IGNORECASE
        ),
        "type": "file_upload_attempt",
        "risk": 35,
        "description": "Suspicious file upload attempt",
    },
    "ldap_injection": {
        "pattern": re.compile(
            r'(\*|\||&|%28|%29|\(\)|admin)',
            re.IGNORECASE
        ),
        "type": "ldap_injection",
        "risk": 30,
        "description": "LDAP injection attempt",
    },
    "xml_injection": {
        "pattern": re.compile(
            r'(<!DOCTYPE|<!ENTITY|<!\[CDATA|xmlns=)',
            re.IGNORECASE
        ),
        "type": "xml_injection",
        "risk": 25,
        "description": "XML injection attempt",
    },
    "csrf_attempt": {
        "pattern": re.compile(
            r'(csrf|xsrf|anticsrf|referer=)',
            re.IGNORECASE
        ),
        "type": "csrf_attempt",
        "risk": 15,
        "description": "CSRF token manipulation",
    },
}


APACHE_ACCESS_PATTERN = re.compile(
    r'^([\d.]+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+'
    r'"(GET|POST|PUT|DELETE|PATCH|HEAD)\s+(\S+)\s+HTTP/[\d.]+\s+(\d+)\s+(\d+|-)\s+'
    r'"([^"]*)"\s+"([^"]*)"'
)

NGINX_ACCESS_PATTERN = re.compile(
    r'^([\d.]+)\s+-\s+\S+\s+\[([^\]]+)\]\s+'
    r'"(GET|POST|PUT|DELETE|PATCH|HEAD)\s+(\S+)\s+HTTP/[\d.]+\s+(\d+)\s+(\d+)\s+'
    r'"([^"]*)"\s+"([^"]*)"'
)

APACHE_ERROR_PATTERN = re.compile(
    r'\[([^\]]+)\]\s+\[([^\]]+)\]\s+(?:\[pid\s+(\d+)\])?\s*(.*)'
)


def parse_apache_access_log(line: str) -> Optional[dict]:
    """
    Parsea una linea de Apache access log en formato Combined Log Format.

    Formato: %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"

    Returns:
        Dict con ip, timestamp, method, path, status, bytes, referer, user_agent
    """
    match = APACHE_ACCESS_PATTERN.match(line)
    if not match:
        return None

    return {
        "ip": match.group(1),
        "timestamp": match.group(2),
        "method": match.group(3),
        "path": match.group(4),
        "status": int(match.group(5)),
        "bytes": match.group(6),
        "referer": match.group(7),
        "user_agent": match.group(8),
    }


def parse_nginx_access_log(line: str) -> Optional[dict]:
    """Parsea una linea de Nginx access log."""
    match = NGINX_ACCESS_PATTERN.match(line)
    if not match:
        return None

    return {
        "ip": match.group(1),
        "timestamp": match.group(2),
        "method": match.group(3),
        "path": match.group(4),
        "status": int(match.group(5)),
        "bytes": match.group(6),
        "referer": match.group(7),
        "user_agent": match.group(8),
    }


def get_patterns_for_source(source: str) -> dict:
    """Obtiene los patrones apropiados para la fuente de log."""
    return WEB_LOG_PATTERNS


def check_injection_patterns(line: str, path: str = "", query: str = "") -> list:
    """
    Verifica si una peticion contiene patrones de inyeccion.

    Args:
        line: Linea completa del log
        path: Path de la peticion
        query: Query string

    Returns:
        Lista de tuplas (pattern_name, pattern_config) con detecciones
    """
    detections = []
    search_text = f"{line} {path} {query}".lower()

    for name, config in WEB_LOG_PATTERNS.items():
        if config["pattern"].search(search_text):
            detections.append((name, config))

    return detections


EVENT_WEIGHTS = {
    "sqli_attempt": 35,
    "xss_attempt": 30,
    "path_traversal": 40,
    "command_injection": 45,
    "scanner_detection": 25,
    "http_flood": 20,
    "suspicious_user_agent": 5,
    "404_enumeration": 10,
    "error_500": 15,
    "error_403": 10,
    "file_upload_attempt": 35,
    "ldap_injection": 30,
    "xml_injection": 25,
    "csrf_attempt": 15,
}


def get_risk_weight(event_type: str) -> int:
    """Obtiene el peso de riesgo para un tipo de evento."""
    return EVENT_WEIGHTS.get(event_type, 10)
