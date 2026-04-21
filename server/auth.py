import os
import bcrypt
import logging
from functools import wraps
from flask import request, jsonify

try:
    from threat_detector import threat_detector
except ImportError:
    threat_detector = None

try:
    from .audit import audit_logger
except ImportError:
    audit_logger = logging.getLogger("audit")

auth_logger = logging.getLogger("auth")

DASHBOARD_USERNAME = os.getenv("DASHBOARD_USERNAME", "admin")
DASHBOARD_PASSWORD_HASH = os.getenv("DASHBOARD_PASSWORD_HASH")
DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASSWORD", "changeme")


def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        ip = request.remote_addr

        if threat_detector and threat_detector.is_blocked(ip):
            auth_logger.warning(f"Blocked IP attempted auth: {ip}")
            return jsonify({
                "status": "error",
                "error": "Access denied",
                "detail": "Your IP has been temporarily blocked"
            }), 403

        auth = request.authorization
        if not auth:
            auth_logger.warning(f"Auth attempt without credentials from {ip}")
            audit_logger.info("AUTH_ATTEMPT", user="unknown", ip=ip, details={"success": False, "reason": "no_credentials"})  # type: ignore
            return jsonify({"status": "error", "error": "Authentication required"}), 401

        username = auth.username
        password = auth.password

        if username != DASHBOARD_USERNAME:
            auth_logger.warning(f"Failed auth attempt for unknown user '{username}' from {ip}")  # type: ignore
            audit_logger.info("AUTH_ATTEMPT", user=username, ip=ip, details={"success": False, "reason": "invalid_user"})  # type: ignore
            return jsonify({"status": "error", "error": "Invalid credentials"}), 401

        auth_success = False
        password_hash = DASHBOARD_PASSWORD_HASH
        if password_hash and isinstance(password_hash, bytes) and password:
            if bcrypt.checkpw(password.encode(), password_hash):  # type: ignore
                auth_success = True
        elif not password_hash and password and password == DASHBOARD_PASSWORD:
            auth_success = True

        if auth_success:
            audit_logger.info("AUTH_ATTEMPT", user=username, ip=ip, details={"success": True})  # type: ignore
            return f(*args, **kwargs)

        auth_logger.warning(f"Failed auth attempt for user '{username}' from {ip}")
        audit_logger.info("AUTH_ATTEMPT", user=username, ip=ip, details={"success": False, "reason": "invalid_password"})  # type: ignore

        if threat_detector:
            threat_detector.record_failed_auth(ip)

        return jsonify({"status": "error", "error": "Invalid credentials"}), 401

    return decorated


def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get("X-API-Key")
        expected_key = os.getenv("DASHBOARD_API_KEY")

        if not expected_key:
            return f(*args, **kwargs)

        if not api_key or api_key != expected_key:
            auth_logger.warning(f"Invalid API key attempt from {request.remote_addr}")
            return jsonify({"status": "error", "error": "Invalid API key"}), 401

        return f(*args, **kwargs)
    return decorated
