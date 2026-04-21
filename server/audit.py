"""
Audit Logger - Registro de todas las acciones en la Dashboard API.

Registra:
- Accesos a endpoints
- Intentos de autenticacion
- Errores y excepciones
- Cambios de configuracion

Uso:
    from audit import audit_logger, audit_log

    audit_logger.info("User accessed dashboard")
"""

import os
import json
import logging
from pathlib import Path
from datetime import datetime
from functools import wraps
from flask import request, g

_SERVER_DIR = Path(__file__).resolve().parent
AUDIT_LOG_FILE = os.getenv("AUDIT_LOG_FILE", str(_SERVER_DIR / "audit.log"))


class AuditLogger:
    def __init__(self, log_file=None):
        self.log_file = log_file or AUDIT_LOG_FILE
        self.logger = logging.getLogger("audit")
        self.logger.setLevel(logging.INFO)

        if not self.logger.handlers:
            handler = logging.FileHandler(self.log_file)
            formatter = logging.Formatter(
                '%(asctime)s | %(levelname)s | %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S.%f'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)

    def log(self, level, action, user=None, ip=None, details=None):
        """Registra una accion en el log de auditoria."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "user": user or "anonymous",
            "ip": ip or request.remote_addr if request else "unknown",
            "details": details or {}
        }

        if hasattr(request, 'endpoint'):
            entry["endpoint"] = request.endpoint
            entry["method"] = request.method

        log_message = json.dumps(entry)
        getattr(self.logger, level)(log_message)

    def info(self, action, user=None, ip=None, details=None):
        self.log("info", action, user, ip, details)

    def warning(self, action, user=None, ip=None, details=None):
        self.log("warning", action, user, ip, details)

    def error(self, action, user=None, ip=None, details=None):
        self.log("error", action, user, ip, details)


audit_logger = AuditLogger()


def audit_log(action, user=None):
    """Decorador para registrar acciones de auditoria."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user_value = user
            if not user_value and hasattr(request, 'authorization'):
                auth = request.authorization
                user_value = auth.username if auth else "anonymous"

            ip = request.remote_addr

            try:
                result = f(*args, **kwargs)
                audit_logger.info(
                    action=action,
                    user=user_value,
                    ip=ip,
                    details={"status": "success", "endpoint": request.endpoint}
                )
                return result
            except Exception as e:
                audit_logger.error(
                    action=action,
                    user=user_value,
                    ip=ip,
                    details={"status": "error", "error": str(e)}
                )
                raise
        return decorated
    return decorator


def log_auth_attempt(username, success, ip=None):
    """Registra intento de autenticacion."""
    audit_logger.info(
        action="AUTH_ATTEMPT",
        user=username,
        ip=ip or request.remote_addr,
        details={"success": success}
    )


def log_access(endpoint, user=None, ip=None):
    """Registra acceso a endpoint."""
    audit_logger.info(
        action="ENDPOINT_ACCESS",
        user=user,
        ip=ip or request.remote_addr,
        details={"endpoint": endpoint}
    )


def log_error(error_type, message, user=None, ip=None):
    """Registra error."""
    audit_logger.error(
        action=error_type,
        user=user,
        ip=ip or request.remote_addr,
        details={"message": message}
    )
