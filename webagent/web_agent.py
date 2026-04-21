"""
Agente de monitoreo de logs de servidores web (Apache, Nginx).

Este agente monitorea access logs y error logs de servidores web para detectar:
- SQL Injection attempts
- Cross-Site Scripting (XSS)
- Path Traversal
- Command Injection
- Security Scanner Detection
- HTTP Flood
- Suspicious User Agents
- Enumeration Attempts (404)
- Server Errors
- File Upload Attempts
- Deteccion basada en correlacion de eventos
- Cooldown para evitar alertas duplicadas
- Persistencia de estado

Uso:
    python agent/web_agent.py

Configuracion (via .env):
    WEB_AGENT_ID=apache-web-01
    WEB_TARGET_HOST=192.168.1.100
    WEB_TARGET_SERVICE=http
    WEB_SOURCE=apache
    WEB_LOG_FILE=/var/log/apache2/access.log
    WEB_SERVER_URL=https://soc-server.com/log
    WEB_API_KEY=your-secret-key
    WEB_USE_BATCH_MODE=true
"""
import logging
import os
import time
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any

from dotenv import load_dotenv

try:
    from .base import AgentBase
    from .patterns import (
        parse_apache_access_log,
        parse_nginx_access_log,
        check_injection_patterns,
        extract_timestamp_from_log as web_extract_timestamp,
    )
except ImportError:
    import sys
    import pathlib
    sys.path.insert(0, str(pathlib.Path(__file__).parent))
    from base import AgentBase  # pylint: disable=reimported
    from patterns import (  # pylint: disable=reimported
        parse_apache_access_log,
        parse_nginx_access_log,
        check_injection_patterns,
        extract_timestamp_from_log as web_extract_timestamp,
    )

try:
    from .persistence import AgentState
except ImportError:
    from persistence import AgentState

load_dotenv(Path(__file__).parent / ".env")

WEB_AGENT_ID = os.environ.get(
    "WEB_AGENT_ID", os.environ.get("AGENT_ID", "web-agent-01")
)
WEB_TARGET_HOST = os.environ.get("WEB_TARGET_HOST", "0.0.0.0")
WEB_TARGET_SERVICE = os.environ.get("WEB_TARGET_SERVICE", "http")
WEB_SOURCE = os.environ.get("WEB_SOURCE", "apache")
WEB_LOG_FILE = os.environ.get("WEB_LOG_FILE")
WEB_SERVER_URL = os.environ.get(
    "WEB_SERVER_URL",
    os.environ.get("SERVER_URL", "https://127.0.0.1:5000/log")
)
WEB_BATCH_URL = os.environ.get(
    "WEB_BATCH_URL",
    WEB_SERVER_URL.replace("/log", "/log/batch", 1)
)
WEB_API_KEY = (
    os.environ.get("WEB_API_KEY")
    or os.environ.get("X_API_KEY")
    or os.environ.get("AGENT_API_KEY")
)
WEB_API_SECRET = os.environ.get("WEB_API_SECRET") or os.environ.get("X_API_KEY_SECRET", "")
WEB_USE_SSL = os.environ.get("WEB_USE_SSL", "true").lower() == "true"
WEB_VERIFY_SSL = os.environ.get("WEB_VERIFY_SSL", "true").lower() == "true"
WEB_AGENT_INTERVAL = int(os.environ.get("WEB_AGENT_INTERVAL", 10))
WEB_REQUEST_TIMEOUT = int(os.environ.get("WEB_REQUEST_TIMEOUT", 10))
WEB_USE_BATCH_MODE = os.environ.get("WEB_USE_BATCH_MODE", "true").lower() == "true"
WEB_BATCH_SIZE = int(os.environ.get("WEB_BATCH_SIZE", 20))
WEB_BATCH_TIMEOUT = int(os.environ.get("WEB_BATCH_TIMEOUT", 30))
WEB_STATE_DIR = os.environ.get("WEB_STATE_DIR") or os.environ.get("STATE_DIR")

WEB_FLOOD_THRESHOLD = int(os.environ.get("WEB_FLOOD_THRESHOLD", 100))
WEB_FLOOD_WINDOW = int(os.environ.get("WEB_FLOOD_WINDOW", 60))
WEB_SUSPICIOUS_404_THRESHOLD = int(
    os.environ.get("WEB_SUSPICIOUS_404_THRESHOLD", 10)
)
WEB_SUSPICIOUS_404_WINDOW = int(os.environ.get("WEB_SUSPICIOUS_404_WINDOW", 300))

WEB_SEND_COOLDOWN = {
    "default": int(os.environ.get("WEB_SEND_COOLDOWN_DEFAULT", 30)),
    "critical": int(os.environ.get("WEB_SEND_COOLDOWN_CRITICAL", 0)),
    "high": int(os.environ.get("WEB_SEND_COOLDOWN_HIGH", 15)),
}


logging.basicConfig(
    level=getattr(logging, os.environ.get("WEB_LOG_LEVEL", "INFO"))
)
logger = logging.getLogger(__name__)

security_logger = logging.getLogger("security")
security_handler = logging.StreamHandler()
security_handler.setFormatter(logging.Formatter(
    '%(levelname)s:web_agent: %(message)s'
))
security_logger.addHandler(security_handler)
security_logger.setLevel(logging.WARNING)
security_logger.propagate = False

state = AgentState(WEB_AGENT_ID, WEB_STATE_DIR)


class WebAgent(AgentBase):
    """
    Agente especializado para monitoreo de logs de servidores web.

    Detecta ataques comunes a aplicaciones web mediante analisis de
    access logs y error logs.
    
    Caracteristicas avanzadas:
    - Cooldown para evitar alertas duplicadas
    - Correlacion de eventos por IP
    - Deteccion de patrones compostos (scanner + ataque)
    - Persistencia de estado entre ejecuciones
    """

    def __init__(self):
        super().__init__(
            agent_id=WEB_AGENT_ID,
            server_url=WEB_SERVER_URL,
            batch_url=WEB_BATCH_URL,
            api_key=WEB_API_KEY or "",
            log_file=WEB_LOG_FILE,
            verify_ssl=WEB_VERIFY_SSL,
            request_timeout=WEB_REQUEST_TIMEOUT,
            use_batch_mode=WEB_USE_BATCH_MODE,
            batch_size=WEB_BATCH_SIZE,
            batch_timeout=WEB_BATCH_TIMEOUT,
            agent_interval=WEB_AGENT_INTERVAL,
            state_dir=WEB_STATE_DIR,
            api_secret=WEB_API_SECRET,
        )

        self.target_host = WEB_TARGET_HOST
        self.target_service = WEB_TARGET_SERVICE
        self.source = WEB_SOURCE

        self.ip_request_counts: Dict[str, list] = defaultdict(list)
        self.ip_404_counts: Dict[str, list] = defaultdict(list)
        self.active_floods: Dict[str, Dict[str, Any]] = {}

    def _clean_old_requests(self, ip: str, window: int):
        """Limpia requests antiguos de una IP."""
        cutoff = datetime.now() - timedelta(seconds=window)
        self.ip_request_counts[ip] = [
            t for t in self.ip_request_counts[ip] if t > cutoff
        ]

    def _should_send(self, ip: str, event_type: str, severity: str) -> bool:
        """Determina si debe enviarse una alerta basado en cooldown."""
        cooldown_seconds = WEB_SEND_COOLDOWN.get(
            severity.lower(), WEB_SEND_COOLDOWN["default"]
        )
        return state.should_send(ip, event_type, severity, cooldown_seconds)

    def _record_event(self, ip: str, event_type: str):
        """Registra evento para correlacion."""
        state.record_ip_event(ip, event_type)

    def _check_correlation(self, ip: str, event_type: str) -> Dict[str, Any]:
        """
        Verifica correlacion de eventos para una IP.
        
        Detecta:
        - Scanner seguido de ataque
        - Multiples tipos de ataque
        - Intensificacion de ataques
        """
        context = {
            "has_scanner": False,
            "has_attack": False,
            "event_count": 0,
            "event_types": [],
            "risk_modifier": 0
        }

        event_count = state.get_ip_event_count(ip)
        if event_count > 0:
            context["event_count"] = event_count

            for event_type in ["scanner_detection", "sqli_attempt", "xss_attempt", 
                            "path_traversal", "command_injection"]:
                if state.get_ip_event_count(ip, event_type) > 0:
                    context["event_types"].append(event_type)
                    if event_type == "scanner_detection":
                        context["has_scanner"] = True
                    else:
                        context["has_attack"] = True

        if context["has_scanner"] and context["has_attack"]:
            context["risk_modifier"] = 20

        if event_count >= 5:
            context["risk_modifier"] += min((event_count - 4) * 5, 20)

        return context

    def _is_http_flood(self, ip: str, log_data: Optional[Dict]) -> bool:
        """Detecta si una IP esta haciendo flood."""
        self._clean_old_requests(ip, WEB_FLOOD_WINDOW)
        self.ip_request_counts[ip].append(datetime.now())

        count = len(self.ip_request_counts[ip])
        if count >= WEB_FLOOD_THRESHOLD and ip not in self.active_floods:
            self.active_floods[ip] = {
                "start_time": datetime.now(),
                "request_count": count,
                "paths": [],
            }
            state.record_ip_event(ip, "http_flood_start")
            return True
        if ip in self.active_floods:
            self.active_floods[ip]["request_count"] = count
            if log_data and "path" in log_data:
                self.active_floods[ip]["paths"].append(log_data["path"])
            return False
        return False

    def _handle_flood_end(self, ip: str):
        """Maneja el fin de un ataque de flood."""
        if ip in self.active_floods:
            flood_data = self.active_floods[ip]
            duration = 0
            try:
                duration = int(
                    (datetime.now() - flood_data["start_time"]).total_seconds()
                )
            except (ValueError, TypeError, KeyError):
                pass

            if duration > 0:
                logger.info(
                    "[%s] HTTP FLOOD END %s duration=%ds requests=%d",
                    self.agent_id,
                    ip,
                    duration,
                    flood_data["request_count"]
                )
                event = self.build_event(
                    "http_flood_end",
                    ip, -5,
                    duration=duration,
                    attempts_count=flood_data["request_count"],
                    extra_data={"paths_touched": len(set(flood_data["paths"]))},
                )
                if self.use_batch_mode:
                    self.send_event_async(event)
                else:
                    self.send_event(event)

            del self.active_floods[ip]

    def _handle_sqli_attempt(
        self, ip: str, port: Optional[int], path: str, log_data: Optional[Dict]
    ):
        """Maneja SQL Injection attempt."""
        if not self._should_send(ip, "sqli_attempt", "HIGH"):
            logger.debug("[%s] Cooldown: sqli from %s", self.agent_id, ip)
            return

        self.update_stats("unique_events")
        state.record_ip_event(ip, "sqli_attempt")
        
        correlation = self._check_correlation(ip, "sqli_attempt")
        base_risk = 35
        risk = min(base_risk + correlation["risk_modifier"], 80)
        
        security_logger.warning("[%s] SQL INJECTION ATTEMPT from %s on %s (risk=%d)", 
                   self.agent_id, ip, path, risk)
        
        extra = {
            "path": path,
            "user_agent": log_data.get("user_agent", "") if log_data else ""
        }
        if correlation["event_count"] > 0:
            extra["correlation"] = correlation
        
        event = self.build_event(
            "sqli_attempt",
            ip, risk,
            src_port=port,
            extra_data=extra,
        )
        if self.use_batch_mode:
            self.send_event_async(event)
        else:
            self.send_event(event)

    def _handle_xss_attempt(
        self, ip: str, port: Optional[int], path: str, log_data: Optional[Dict]
    ):
        """Maneja XSS attempt."""
        if not self._should_send(ip, "xss_attempt", "HIGH"):
            logger.debug("[%s] Cooldown: xss from %s", self.agent_id, ip)
            return

        self.update_stats("unique_events")
        state.record_ip_event(ip, "xss_attempt")
        
        correlation = self._check_correlation(ip, "xss_attempt")
        base_risk = 30
        risk = min(base_risk + correlation["risk_modifier"], 75)
        
        security_logger.warning("[%s] XSS ATTEMPT from %s on %s (risk=%d)", 
                   self.agent_id, ip, path, risk)
        
        extra = {
            "path": path,
            "user_agent": log_data.get("user_agent", "") if log_data else ""
        }
        if correlation["event_count"] > 0:
            extra["correlation"] = correlation
        
        event = self.build_event(
            "xss_attempt",
            ip, risk,
            src_port=port,
            extra_data=extra,
        )
        if self.use_batch_mode:
            self.send_event_async(event)
        else:
            self.send_event(event)

    def _handle_path_traversal(
        self, ip: str, port: Optional[int], path: str, log_data: Optional[Dict]
    ):
        """Maneja Path Traversal attempt."""
        if not self._should_send(ip, "path_traversal", "HIGH"):
            logger.debug("[%s] Cooldown: path_traversal from %s", self.agent_id, ip)
            return

        self.update_stats("unique_events")
        state.record_ip_event(ip, "path_traversal")
        
        correlation = self._check_correlation(ip, "path_traversal")
        base_risk = 40
        risk = min(base_risk + correlation["risk_modifier"], 85)
        
        security_logger.warning("[%s] PATH TRAVERSAL ATTEMPT from %s on %s (risk=%d)", 
                   self.agent_id, ip, path, risk)
        
        extra = {
            "path": path,
            "user_agent": log_data.get("user_agent", "") if log_data else ""
        }
        if correlation["event_count"] > 0:
            extra["correlation"] = correlation
        
        event = self.build_event(
            "path_traversal",
            ip, risk,
            src_port=port,
            extra_data=extra,
        )
        if self.use_batch_mode:
            self.send_event_async(event)
        else:
            self.send_event(event)

    def _handle_command_injection(
        self, ip: str, port: Optional[int], path: str, log_data: Optional[Dict]
    ):
        """Maneja Command Injection attempt."""
        if not self._should_send(ip, "command_injection", "CRITICAL"):
            logger.debug("[%s] Cooldown: command_injection from %s", self.agent_id, ip)
            return

        self.update_stats("unique_events")
        state.record_ip_event(ip, "command_injection")
        
        correlation = self._check_correlation(ip, "command_injection")
        base_risk = 45
        risk = min(base_risk + correlation["risk_modifier"], 90)
        
        security_logger.warning("[%s] COMMAND INJECTION ATTEMPT from %s on %s (risk=%d)", 
                   self.agent_id, ip, path, risk)
        
        extra = {
            "path": path,
            "user_agent": log_data.get("user_agent", "") if log_data else ""
        }
        if correlation["event_count"] > 0:
            extra["correlation"] = correlation
        
        event = self.build_event(
            "command_injection",
            ip, risk,
            src_port=port,
            extra_data=extra,
        )
        if self.use_batch_mode:
            self.send_event_async(event)
        else:
            self.send_event(event)

    def _handle_scanner_detection(
        self, ip: str, port: Optional[int], path: str, log_data: Optional[Dict]
    ):
        """Maneja deteccion de scanner."""
        if not self._should_send(ip, "scanner_detection", "MEDIUM"):
            logger.debug("[%s] Cooldown: scanner from %s", self.agent_id, ip)
            return

        self.update_stats("unique_events")
        state.record_ip_event(ip, "scanner_detection")
        
        user_agent = log_data.get("user_agent", "unknown") if log_data else "unknown"
        correlation = self._check_correlation(ip, "scanner_detection")
        
        logger.warning("[%s] SCANNER DETECTED %s (%s) on %s", 
                      self.agent_id, ip, user_agent, path)
        
        extra = {
            "path": path,
            "user_agent": user_agent,
        }
        if correlation["event_count"] > 0:
            extra["correlation"] = correlation
        
        event = self.build_event(
            "scanner_detection",
            ip, 25,
            src_port=port,
            extra_data=extra,
        )
        if self.use_batch_mode:
            self.send_event_async(event)
        else:
            self.send_event(event)

    def _handle_404_enumeration(
        self, ip: str, port: Optional[int], path: str
    ):
        """Maneja 404 enumeration (muchos 404 de una misma IP)."""
        cutoff = datetime.now() - timedelta(seconds=WEB_SUSPICIOUS_404_WINDOW)
        self.ip_404_counts[ip] = [
            t for t in self.ip_404_counts[ip] if t > cutoff
        ]
        self.ip_404_counts[ip].append(datetime.now())

        if len(self.ip_404_counts[ip]) >= WEB_SUSPICIOUS_404_THRESHOLD:
            count = len(self.ip_404_counts[ip])
            
            if not self._should_send(ip, "404_enumeration", "MEDIUM"):
                logger.debug("[%s] Cooldown: 404_enum from %s", self.agent_id, ip)
                return
            
            state.record_ip_event(ip, "404_enumeration")
            logger.warning("[%s] 404 ENUMERATION from %s (%d requests)", 
                          self.agent_id, ip, count)
            event = self.build_event(
                "404_enumeration",
                ip, 10,
                src_port=port,
                attempts_count=count,
                extra_data={"paths": list(set([path]))},
            )
            if self.use_batch_mode:
                self.send_event_async(event)
            else:
                self.send_event(event)
            self.ip_404_counts[ip] = []

    def _handle_file_upload_attempt(
        self, ip: str, port: Optional[int], path: str, log_data: Optional[Dict]
    ):
        """Maneja intentos de subida de archivos suspiciousos."""
        if not self._should_send(ip, "file_upload_attempt", "HIGH"):
            logger.debug("[%s] Cooldown: file_upload from %s", self.agent_id, ip)
            return

        self.update_stats("unique_events")
        state.record_ip_event(ip, "file_upload_attempt")
        
        method = log_data.get("method", "POST") if log_data else "POST"
        logger.warning("[%s] FILE UPLOAD ATTEMPT from %s on %s", 
                     self.agent_id, ip, path)
        
        extra = {"path": path, "method": method}
        correlation = self._check_correlation(ip, "file_upload_attempt")
        if correlation["event_count"] > 0:
            extra["correlation"] = correlation
        
        event = self.build_event(
            "file_upload_attempt",
            ip, 35,
            src_port=port,
            extra_data=extra,
        )
        if self.use_batch_mode:
            self.send_event_async(event)
        else:
            self.send_event(event)

    def _parse_log_line(self, line: str):
        """
        Intenta parsear una linea de log con diferentes parsers.

        Returns:
            Tupla (parsed_data, source_type) o (None, None)
        """
        log_data = parse_apache_access_log(line)
        if log_data:
            return log_data, "apache"

        log_data = parse_nginx_access_log(line)
        if log_data:
            return log_data, "nginx"

        return None, None

    def monitor(self):
        """Monitorea el archivo de log y detecta ataques web."""
        lines = self.read_log_lines()

        for line in lines:
            self.update_stats("logs_processed")
            line = line.strip()

            if not line:
                continue

            if self.is_processed(line):
                self.update_stats("logs_duplicated")
                logger.debug("[%s] Log duplicado, ignorando", self.agent_id)
                continue

            self.mark_processed(line)

            log_timestamp = web_extract_timestamp(line)
            log_data, _ = self._parse_log_line(line)

            if not log_data:
                self.update_stats("logs_filtered")
                continue

            ip = str(log_data.get("ip") or "")
            if not ip or ip == "None":
                self.update_stats("logs_filtered")
                continue

            path = log_data.get("path", "") or ""
            method = log_data.get("method", "GET") or "GET"
            status = log_data.get("status", 200) or 200

            if self._is_http_flood(ip, log_data):
                count = len(self.ip_request_counts[ip])
                logger.warning(
                    "[%s] HTTP FLOOD START from %s (threshold=%d)",
                    self.agent_id, ip, count
                )
                event = self.build_event(
                    "http_flood_start",
                    ip, 25,
                    attempts_count=count,
                    extra_data={"paths": list(set([path]))},
                    log_timestamp=log_timestamp,
                )
                if self.use_batch_mode:
                    self.send_event_async(event)
                else:
                    self.send_event(event)

            if status == 404:
                self._handle_404_enumeration(ip, None, path)

            if status == 403:
                logger.info(
                    "[%s] 403 Forbidden from %s on %s",
                    self.agent_id, ip, path
                )
                event = self.build_event(
                    "error_403",
                    ip, 10,
                    extra_data={"path": path},
                    log_timestamp=log_timestamp,
                )
                if self.use_batch_mode:
                    self.send_event_async(event)
                else:
                    self.send_event(event)

            if status >= 500:
                logger.warning(
                    "[%s] Server Error %d from %s on %s",
                    self.agent_id, status, ip, path
                )
                event = self.build_event(
                    "error_500",
                    ip, 15,
                    extra_data={"status": status, "path": path},
                    log_timestamp=log_timestamp,
                )
                if self.use_batch_mode:
                    self.send_event_async(event)
                else:
                    self.send_event(event)

            detections = check_injection_patterns(line, path, "")

            for pattern_name, _ in detections:
                if pattern_name == "sqli_attempt":
                    self._handle_sqli_attempt(ip, None, path, log_data)
                elif pattern_name == "xss_attempt":
                    self._handle_xss_attempt(ip, None, path, log_data)
                elif pattern_name == "path_traversal":
                    self._handle_path_traversal(ip, None, path, log_data)
                elif pattern_name == "command_injection":
                    self._handle_command_injection(ip, None, path, log_data)
                elif pattern_name == "scanner_detection":
                    self._handle_scanner_detection(ip, None, path, log_data)
                elif pattern_name == "file_upload_attempt":
                    self._handle_file_upload_attempt(ip, None, path, log_data)

            if method == "POST" and any(
                kw in path.lower() for kw in ["upload", "save", "attach", "file"]
            ):
                self._handle_file_upload_attempt(ip, None, path, log_data)

        for flood_ip in list(self.active_floods.keys()):
            if flood_ip in self.ip_request_counts:
                self._clean_old_requests(flood_ip, WEB_FLOOD_WINDOW)
                if len(self.ip_request_counts[flood_ip]) < WEB_FLOOD_THRESHOLD / 2:
                    self._handle_flood_end(flood_ip)

        self._save_state()


def main():
    """Punto de entrada principal."""
    errors = []

    if not WEB_API_KEY:
        errors.append("WEB_API_KEY no configurada")

    if not WEB_LOG_FILE:
        errors.append("WEB_LOG_FILE no configurado en .env (ej: WEB_LOG_FILE=data/web_access.log)")

    if errors:
        logger.error("Errores de configuracion:")
        for err in errors:
            logger.error("  - %s", err)
        return

    agent = WebAgent()
    agent.run()


if __name__ == "__main__":
    main()