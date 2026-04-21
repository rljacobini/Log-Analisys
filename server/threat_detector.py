"""
ThreatDetector - Deteccion de amenazas para la Dashboard API.

Detecta y bloquea:
- Intentos de fuerza bruta (autenticacion fallida)
- Abuso de rate limiting
- Patrones de ataque conocidos

Uso:
    from threat_detector import threat_detector, is_ip_blocked

    if is_ip_blocked(request.remote_addr):
        return jsonify({"error": "IP blocked"}), 403

    threat_detector.record_failed_auth(request.remote_addr)
"""

import os
import re
import logging
from datetime import datetime, timedelta
from collections import defaultdict
from functools import wraps
from flask import request, jsonify

threat_logger = logging.getLogger("threat")

THREAT_THRESHOLD_AUTH = int(os.getenv("THREAT_THRESHOLD_AUTH", "5"))
THREAT_THRESHOLD_RATE = int(os.getenv("THREAT_THRESHOLD_RATE", "10"))
THREAT_WINDOW_MINUTES = int(os.getenv("THREAT_WINDOW_MINUTES", "15"))
BLOCKED_IPS_FILE = os.getenv("BLOCKED_IPS_FILE", "blocked_ips.txt")


class ThreatDetector:
    def __init__(self):
        self.failed_auth = defaultdict(list)
        self.rate_limit_violations = defaultdict(int)
        self.blocked_ips = set()
        self._load_blocked_ips()
        self.threshold_auth = THREAT_THRESHOLD_AUTH
        self.threshold_rate = THREAT_THRESHOLD_RATE
        self.window_minutes = THREAT_WINDOW_MINUTES

    def _load_blocked_ips(self):
        """Carga IPs bloqueadas desde archivo."""
        if os.path.exists(BLOCKED_IPS_FILE):
            try:
                with open(BLOCKED_IPS_FILE, 'r', encoding='utf-8') as f:
                    for line in f:
                        ip = line.strip()
                        if ip:
                            self.blocked_ips.add(ip)
                threat_logger.info(f"Loaded {len(self.blocked_ips)} blocked IPs")
            except Exception as e:
                threat_logger.error(f"Error loading blocked IPs: {e}")

    def _save_blocked_ips(self):
        """Guarda IPs bloqueadas a archivo."""
        try:
            with open(BLOCKED_IPS_FILE, 'w', encoding='utf-8') as f:
                for ip in self.blocked_ips:
                    f.write(f"{ip}\n")
        except Exception as e:
            threat_logger.error(f"Error saving blocked IPs: {e}")

    def record_failed_auth(self, ip):
        """Registra intento de autenticacion fallido."""
        now = datetime.now()
        cutoff = now - timedelta(minutes=self.window_minutes)

        self.failed_auth[ip] = [t for t in self.failed_auth[ip] if t > cutoff]
        self.failed_auth[ip].append(now)

        threat_logger.warning(
            f"Failed auth from {ip}: {len(self.failed_auth[ip])} attempts in {self.window_minutes} min"
        )

        if len(self.failed_auth[ip]) > self.threshold_auth:
            self.block_ip(ip, "BRUTE_FORCE_AUTH")
            return True
        return False

    def record_rate_limit_violation(self, ip):
        """Registra violacion de rate limiting."""
        self.rate_limit_violations[ip] += 1

        threat_logger.warning(
            f"Rate limit violation from {ip}: {self.rate_limit_violations[ip]} violations"
        )

        if self.rate_limit_violations[ip] > self.threshold_rate:
            self.block_ip(ip, "RATE_LIMIT_ABUSE")
            return True
        return False

    def block_ip(self, ip, reason):
        """Bloquea una IP."""
        if ip not in self.blocked_ips:
            self.blocked_ips.add(ip)
            self._save_blocked_ips()
            threat_logger.warning(f"IP blocked: {ip} - Reason: {reason}")

    def unblock_ip(self, ip):
        """Desbloquea una IP."""
        if ip in self.blocked_ips:
            self.blocked_ips.discard(ip)
            self._save_blocked_ips()
            threat_logger.info(f"IP unblocked: {ip}")

    def is_blocked(self, ip):
        """Verifica si una IP esta bloqueada."""
        return ip in self.blocked_ips

    def get_blocked_ips(self):
        """Retorna lista de IPs bloqueadas."""
        return list(self.blocked_ips)

    def clear_violations(self, ip):
        """Limpia violaciones para una IP."""
        self.failed_auth.pop(ip, None)
        self.rate_limit_violations.pop(ip, None)

    def get_stats(self):
        """Retorna estadisticas del detector."""
        return {
            "blocked_ips": len(self.blocked_ips),
            "tracked_auth_failures": len(self.failed_auth),
            "tracked_rate_violations": len(self.rate_limit_violations),
            "threshold_auth": self.threshold_auth,
            "threshold_rate": self.threshold_rate,
            "window_minutes": self.window_minutes
        }


threat_detector = ThreatDetector()


def is_ip_blocked(ip):
    """Verifica si una IP esta bloqueada."""
    return threat_detector.is_blocked(ip)


def require_not_blocked(f):
    """Decorador que rechaza IPs bloqueadas."""
    @wraps(f)
    def decorated(*args, **kwargs):
        ip = request.remote_addr
        if is_ip_blocked(ip):
            threat_logger.warning(f"Blocked IP attempted access: {ip}")
            return jsonify({
                "status": "error",
                "error": "Access denied",
                "detail": "Your IP has been temporarily blocked"
            }), 403
        return f(*args, **kwargs)
    return decorated


def validate_input_safety(value, field_name="input"):
    """
    Valida que un input no contenga patrones suspicious.

    Args:
        value: Valor a validar
        field_name: Nombre del campo para logging

    Returns:
        tuple: (is_valid, error_message)
    """
    if not value:
        return True, None

    suspicious_patterns = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)",
        r"(--|;|/\*|\*/)",
        r"(<script|javascript:|onerror=|onclick=)",
        r"(union\s+select|order\s+by\s+\d+)",
        r"(\bor\b.*=.*\bor\b)",
    ]

    value_lower = str(value).lower()
    for pattern in suspicious_patterns:
        if re.search(pattern, value_lower, re.IGNORECASE):
            threat_logger.warning(
                f"Suspicious input detected in {field_name}: {value[:50]}... from {request.remote_addr}"
            )
            return False, f"Suspicious pattern detected in {field_name}"

    return True, None
