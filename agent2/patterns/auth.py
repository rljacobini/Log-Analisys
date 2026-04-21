"""
Patrones para logs de autenticacion (auth.log, secure).

Monitorea:
- SSH login attempts
- sudo failures
- PAM authentication
- Session events
"""
import re
from datetime import datetime
from typing import Optional, Tuple, Callable


AUTH_TIMESTAMP_PATTERN = re.compile(
    r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
)


def extract_timestamp_from_log(line: str) -> Optional[datetime]:
    """
    Extrae la marca de tiempo de una linea de log syslog.

    Soporta formatos:
    - Syslog: 'Apr 16 10:00:00'

    Args:
        line: Linea de log original

    Returns:
        Objeto datetime o None si no se puede parsear
    """
    match = AUTH_TIMESTAMP_PATTERN.search(line)
    if match:
        timestamp_str = match.group(1)
        try:
            current_year = datetime.now().year
            dt = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
            dt = dt.replace(year=current_year)
            return dt
        except ValueError:
            pass
    return None


def format_log_timestamp(dt: Optional[datetime]) -> str:
    """Formatea un datetime para usar en eventos en formato ISO 8601."""
    if dt:
        return dt.isoformat()
    return datetime.now().isoformat()


AUTH_LOG_PATTERNS = {
    "ssh_failed_password": {
        "pattern": re.compile(
            r'Failed password for (\w+) from (\S+) port (\d+)'
        ),
        "type": "ssh_brute_force",
        "risk": 5,
        "extract_ip": lambda m: m.group(2),
        "extract_user": lambda m: m.group(1),
        "extract_port": lambda m: int(m.group(3)) if m.group(3).isdigit() else None,
    },
    "ssh_accepted_password": {
        "pattern": re.compile(
            r'Accepted password for (\w+) from (\S+) port (\d+)'
        ),
        "type": "ssh_login_success",
        "risk": 20,
        "extract_ip": lambda m: m.group(2),
        "extract_user": lambda m: m.group(1),
        "extract_port": lambda m: int(m.group(3)) if m.group(3).isdigit() else None,
    },
    "ssh_invalid_user": {
        "pattern": re.compile(
            r'Invalid user (\w+) from (\S+) port (\d+)'
        ),
        "type": "ssh_invalid_user",
        "risk": 8,
        "extract_ip": lambda m: m.group(2),
        "extract_user": lambda m: m.group(1),
        "extract_port": lambda m: int(m.group(3)) if m.group(3).isdigit() else None,
    },
    "ssh_disconnected": {
        "pattern": re.compile(
            r'Connection closed by (\S+) port (\d+)'
        ),
        "type": "ssh_connection_closed",
        "risk": 1,
        "extract_ip": lambda m: m.group(1),
        "extract_port": lambda m: int(m.group(2)) if m.group(2).isdigit() else None,
    },
    "ssh_timeout": {
        "pattern": re.compile(
            r'Timeout before authentication from (\S+) port (\d+)'
        ),
        "type": "ssh_timeout",
        "risk": 3,
        "extract_ip": lambda m: m.group(1),
        "extract_port": lambda m: int(m.group(2)) if m.group(2).isdigit() else None,
    },
    "ssh_max_auth": {
        "pattern": re.compile(
            r'maximum authentication attempts exceeded for (\w+) from (\S+)'
        ),
        "type": "ssh_max_attempts",
        "risk": 15,
        "extract_ip": lambda m: m.group(2),
        "extract_user": lambda m: m.group(1),
    },
    "ssh_pubkey_accepted": {
        "pattern": re.compile(
            r'Accepted publickey for (\w+) from (\S+) port (\d+)'
        ),
        "type": "ssh_pubkey_success",
        "risk": 10,
        "extract_ip": lambda m: m.group(2),
        "extract_user": lambda m: m.group(1),
    },
    "ssh_connection_from": {
        "pattern": re.compile(
            r'Connection from (\S+) port (\d+)'
        ),
        "type": "ssh_connection",
        "risk": 1,
        "extract_ip": lambda m: m.group(1),
        "extract_port": lambda m: int(m.group(2)) if m.group(2).isdigit() else None,
    },
    "sudo_failed": {
        "pattern": re.compile(
            r'FAILED LOGIN (\d+) on /dev/tty/ for (\w+), authentication failure'
        ),
        "type": "sudo_failure",
        "risk": 10,
        "extract_user": lambda m: m.group(2),
    },
    "pam_auth_failure": {
        "pattern": re.compile(
            r'auth failure.*user=(\w+).*rhost=(\S+)'
        ),
        "type": "pam_auth_failure",
        "risk": 5,
        "extract_user": lambda m: m.group(1),
        "extract_ip": lambda m: m.group(2),
    },
    "session_opened": {
        "pattern": re.compile(
            r'session opened for user (\w+) by \(uid=(\d+)\)'
        ),
        "type": "session_opened",
        "risk": 2,
        "extract_user": lambda m: m.group(1),
    },
    "session_closed": {
        "pattern": re.compile(
            r'session closed for user (\w+)'
        ),
        "type": "session_closed",
        "risk": 1,
        "extract_user": lambda m: m.group(1),
    },
}


IPTABLES_PATTERNS = {
    "blocked_incoming": {
        "pattern": re.compile(
            r'IN=\w+.*?SRC=(\S+).*?DST=(\S+).*?PROTO=(\w+).*?DPT=(\d+)'
        ),
        "type": "iptables_blocked",
        "risk": 3,
        "extract_src_ip": lambda m: m.group(1),
        "extract_dst_ip": lambda m: m.group(2),
        "extract_protocol": lambda m: m.group(3),
        "extract_dst_port": lambda m: int(m.group(4)) if m.group(4).isdigit() else None,
    },
    "dropped_packet": {
        "pattern": re.compile(r'DROP.*?SRC=(\S+).*?DST=(\S+)'),
        "type": "iptables_drop",
        "risk": 1,
        "extract_src_ip": lambda m: m.group(1),
        "extract_dst_ip": lambda m: m.group(2),
    },
    "accepted_packet": {
        "pattern": re.compile(r'ACCEPT.*?SRC=(\S+).*?DST=(\S+).*?PROTO=(\w+)'),
        "type": "iptables_accept",
        "risk": 1,
        "extract_src_ip": lambda m: m.group(1),
    },
}


SURICATA_PATTERNS = {
    "alert": {
        "pattern": re.compile(
            r'\[(\d+:\S+:\d+)\] (\S+) \[.*?\] SRC=(\S+) DST=(\S+) SPT=(\d+) DPT=(\d+)'
        ),
        "type": "ids_alert",
        "risk": 10,
        "extract_sid": lambda m: m.group(1),
        "extract_class": lambda m: m.group(2),
        "extract_src_ip": lambda m: m.group(3),
        "extract_dst_ip": lambda m: m.group(4),
        "extract_src_port": lambda m: int(m.group(5)) if m.group(5).isdigit() else None,
        "extract_dst_port": lambda m: int(m.group(6)) if m.group(6).isdigit() else None,
    },
    "stream_event": {
        "pattern": re.compile(r'Stream \w+ SRC=(\S+)'),
        "type": "ids_stream",
        "risk": 5,
        "extract_src_ip": lambda m: m.group(1),
    },
}


EVENT_WEIGHTS = {
    "ssh_brute_force": 5,
    "ssh_login_success": 20,
    "ssh_pubkey_success": 10,
    "ssh_invalid_user": 8,
    "ssh_connection_closed": 1,
    "ssh_timeout": 3,
    "ssh_max_attempts": 15,
    "sudo_failure": 10,
    "pam_auth_failure": 5,
    "session_opened": 2,
    "session_closed": 1,
    "iptables_blocked": 3,
    "iptables_drop": 1,
    "iptables_accept": 1,
    "ids_alert": 10,
    "ids_stream": 5,
}


ATTACK_SEVERITY = {
    "brute_force_start": "HIGH",
    "brute_force_end": "LOW",
    "brute_force_critical": "CRITICAL",
    "ssh_login_success": "MEDIUM",
    "ssh_login_success_after_bruteforce": "CRITICAL",
    "ssh_pubkey_success": "LOW",
    "unauthorized_access": "CRITICAL",
    "flooding_detected": "HIGH",
    "port_scan_detected": "MEDIUM",
}


def get_patterns_for_source(source: str) -> dict:
    """Obtiene los patrones apropiados para la fuente de log."""
    source_lower = source.lower()

    if "auth" in source_lower or "secure" in source_lower or "ssh" in source_lower:
        return AUTH_LOG_PATTERNS
    elif "iptables" in source_lower or "kern" in source_lower or "firewall" in source_lower:
        return IPTABLES_PATTERNS
    elif "suricata" in source_lower or "ids" in source_lower or "alert" in source_lower:
        return SURICATA_PATTERNS
    else:
        return AUTH_LOG_PATTERNS


def get_risk_weight(event_type: str) -> int:
    """Obtiene el peso de riesgo para un tipo de evento."""
    return EVENT_WEIGHTS.get(event_type, 5)


def determine_severity(risk: int) -> str:
    """Determina la severidad basada en el riesgo."""
    if risk >= 50:
        return "CRITICAL"
    elif risk >= 30:
        return "HIGH"
    elif risk >= 15:
        return "MEDIUM"
    return "LOW"
