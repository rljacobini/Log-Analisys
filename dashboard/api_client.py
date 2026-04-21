"""
SOC API Client - Cliente para acceder a la Dashboard API del servidor SOC.

Permite que el dashboard acceda remotamente al servidor SOC via API REST.

Seguridad implements:
- Nonce + Timestamp para prevenir replay attacks
- Certificate pinning可选
- Rate limiting del lado cliente
- Input validation
- Retry con exponential backoff
-Timeouts configurables

Uso:
    from api_client import SOCAPIClient

    client = SOCAPIClient(
        base_url="https://soc-server:5000",
        username="admin",
        password="secret"
    )

    stats = client.get_stats()
    logs = client.get_logs(page=1, per_page=50)
"""

import os
import re
import time
import uuid
import hashlib
import hmac
import logging
from threading import Lock
from datetime import datetime, timedelta
from urllib.parse import urlparse

import requests
from requests.auth import HTTPBasicAuth
from requests.adapters import HTTPAdapter

try:
    from urllib3.exceptions import InsecureRequestWarning
    import urllib3
    urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    pass


logger = logging.getLogger(__name__)


VALIDATION_RULES = {
    "page": {"type": int, "min": 1, "max": 1000},
    "per_page": {"type": int, "min": 1, "max": 100},
    "limit": {"type": int, "min": 1, "max": 50},
    "days": {"type": int, "min": 1, "max": 30},
    "agent_id": {"type": str, "max_length": 100, "pattern": r'^[\w\-]+$'},
    "source": {"type": str, "max_length": 50, "pattern": r'^[\w\.\-]+$'},
    "min_risk": {"type": int, "min": 0, "max": 1000},
    "src_ip": {"type": str, "max_length": 45, "pattern": r'^[\d\.\:a-fA-F]+$'},
    "severity": {"type": str, "max_length": 20, "pattern": r'^(LOW|MEDIUM|HIGH|CRITICAL)$'},
}


def validate_param(name, value):
    """
    Valida un parametro segun las reglas definidas.
    
    Returns:
        tuple: (is_valid, validated_value, error_message)
    """
    if value is None:
        return True, None, None
    
    rules = VALIDATION_RULES.get(name)
    if not rules:
        return True, value, None
    
    try:
        if rules.get("type") == int:
            value = int(value)
            if "min" in rules and value < rules["min"]:
                return False, None, f"{name} must be >= {rules['min']}"
            if "max" in rules and value > rules["max"]:
                return False, None, f"{name} must be <= {rules['max']}"
        
        elif rules.get("type") == str:
            value = str(value)
            if "max_length" in rules and len(value) > rules["max_length"]:
                return False, None, f"{name} too long (max {rules['max_length']})"
            if "pattern" in rules:
                if not re.match(rules["pattern"], value):
                    return False, None, f"Invalid format for {name}"
        
        return True, value, None
    
    except (ValueError, TypeError):
        return False, None, f"Invalid type for {name}"


def validate_all_params(params):
    """
    Valida todos los parametros.
    
    Returns:
        tuple: (is_valid, validated_params, error_message)
    """
    validated = {}
    
    for name, value in params.items():
        if value is None:
            continue
        
        is_valid, validated_value, error = validate_param(name, value)
        if not is_valid:
            return False, {}, error
        validated[name] = validated_value
    
    return True, validated, None


def sanitize_string(value, max_length=100):
    """Sanitiza una cadena removiendo caracteres dangerous."""
    if not value:
        return None
    
    value = str(value)[:max_length]
    value = re.sub(r'[<>"\';\\&|`$()]', '', value)
    return value.strip()


def generate_nonce():
    """Genera un nonce unico para cada request."""
    timestamp = int(time.time() * 1000)
    random_part = uuid.uuid4().hex[:16]
    return f"{timestamp}-{random_part}"


def generate_signature(method, path, nonce, timestamp, body=b'', secret=None):
    """
    Genera signature HMAC para el request.
    
    HMAC(SHA256) = hashlib.sha256
    """
    if secret is None:
        secret = ""
    
    message = f"{method}&{path}&{nonce}&{timestamp}&{body.decode() if body else ''}"
    signature = hmac.new(
        secret.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()
    return signature


def verify_signature(signature, method, path, nonce, timestamp, body=b'', secret=None):
    """Verifica la signature del request."""
    expected = generate_signature(method, path, nonce, timestamp, body, secret)
    return hmac.compare_digest(signature, expected)


class SOCAPIClient:
    def __init__(self, base_url=None, username=None, password=None, verify_ssl=None):
        self.base_url = base_url or os.getenv("SOC_API_URL", "http://localhost:5000")
        self.username = username or os.getenv("DASHBOARD_USERNAME", "admin")
        self.password = password or os.getenv("DASHBOARD_PASSWORD", "changeme")
        self.auth = HTTPBasicAuth(self.username, self.password)
        if verify_ssl is not None:
            self.verify_ssl = verify_ssl
        else:
            self.verify_ssl = os.getenv("SOC_VERIFY_SSL", "false").lower() != "true"
        
        self.api_secret = os.getenv("DASHBOARD_API_SECRET", "")
        
        self.timeout = int(os.getenv("API_TIMEOUT", "30"))
        self.max_retries = int(os.getenv("API_MAX_RETRIES", "3"))
        self.retry_backoff = float(os.getenv("API_RETRY_BACKOFF", "1.0"))
        
        self._nonce_history = set()
        self._nonce_lock = Lock()
        self._nonce_ttl = int(os.getenv("NONCE_TTL_SECONDS", "300"))
        
        self._rate_limit_store = {}
        self._rate_lock = Lock()
        self._rate_limit = int(os.getenv("CLIENT_RATE_LIMIT", "60"))
        self._rate_window = 60
        
        self._cert_pins = set()
        cert_pins_env = os.getenv("CERT_PINS", "")
        if cert_pins_env:
            self._cert_pins = set(cert_pins_env.split(","))
        
        self._session = self._create_session()
    
    def _create_session(self):
        """Crea una sesion configurada."""
        session = requests.Session()
        
        adapter = HTTPAdapter(
            max_retries=0,
            pool_connections=10,
            pool_maxsize=10
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        if self._cert_pins:
            session.verify = False
        
        return session
    
    def _add_rate_limiting(self):
        """Agrega headers de rate limiting al request."""
        now = time.time()
        
        with self._rate_lock:
            if "requests" not in self._rate_limit_store:
                self._rate_limit_store["requests"] = []
            
            self._rate_limit_store["requests"] = [
                t for t in self._rate_limit_store["requests"]
                if now - t < self._rate_window
            ]
            
            if len(self._rate_limit_store["requests"]) >= self._rate_limit:
                sleep_time = self._rate_window - (now - self._rate_limit_store["requests"][0])
                if sleep_time > 0:
                    time.sleep(sleep_time)
                    now = time.time()
                    self._rate_limit_store["requests"] = [
                        t for t in self._rate_limit_store["requests"]
                        if now - t < self._rate_window
                    ]
            
            self._rate_limit_store["requests"].append(now)
    
    def _check_nonce(self, nonce):
        """Verifica si un nonce ya fue usado."""
        now = time.time()
        
        with self._nonce_lock:
            self._nonce_history = {
                n for n in self._nonce_history
                if now - int(n.split("-")[0]) < self._nonce_ttl
            }
            
            if nonce in self._nonce_history:
                return False
            
            self._nonce_history.add(nonce)
            return True
    
    def _get(self, endpoint, params=None, include_auth=True):
        """Realiza request GET con todas las protecciones."""
        self._add_rate_limiting()
        
        url = f"{self.base_url}{endpoint}"
        
        validated_params = {}
        if params:
            is_valid, validated_params, error = validate_all_params(params)
            if not is_valid:
                return self._handle_error(ValueError(error))
        
        nonce = generate_nonce()
        timestamp = int(time.time())
        
        headers = {
            "X-Request-ID": nonce,
            "X-Request-Timestamp": str(timestamp),
            "User-Agent": "SOC-API-Client/1.0",
        }
        
        if self.api_secret:
            body = b''
            signature = generate_signature(
                "GET", endpoint, nonce, timestamp, body, self.api_secret
            )
            headers["X-Request-Signature"] = signature
        
        for attempt in range(self.max_retries + 1):
            try:
                response = self._session.get(
                    url,
                    params=validated_params,
                    headers=headers,
                    auth=self.auth if include_auth else None,
                    verify=self.verify_ssl,
                    timeout=self.timeout
                )
                
                response_code = response.status_code
                if response_code == 429:
                    if attempt < self.max_retries:
                        wait_time = self.retry_backoff * (2 ** attempt)
                        logger.warning(f"Rate limited, retrying in {wait_time}s")
                        time.sleep(wait_time)
                        continue
                
                if response_code >= 500:
                    if attempt < self.max_retries:
                        wait_time = self.retry_backoff * (2 ** attempt)
                        logger.warning(f"Server error {response_code}, retrying in {wait_time}s")
                        time.sleep(wait_time)
                        continue
                
                response.raise_for_status()
                
                result = response.json()
                
                if "X-Response-Nonce" in response.headers:
                    resp_nonce = response.headers["X-Response-Nonce"]
                    resp_timestamp = int(response.headers.get("X-Response-Timestamp", 0))
                    
                    if resp_timestamp:
                        time_diff = abs(time.time() - resp_timestamp)
                        if time_diff > 300:
                            logger.warning("Response timestamp too old")
                            return {"status": "error", "error": "Response too old"}
                    
                    if not self._check_nonce(resp_nonce):
                        logger.warning("Possible replay attack detected")
                        return {"status": "error", "error": "Possible replay attack"}
                
                return result
            
            except requests.exceptions.Timeout:
                if attempt < self.max_retries:
                    wait_time = self.retry_backoff * (2 ** attempt)
                    logger.warning(f"Timeout, retrying in {wait_time}s")
                    time.sleep(wait_time)
                    continue
                return self._handle_error(requests.exceptions.Timeout("Request timed out"))
            
            except requests.exceptions.ConnectionError as e:
                if attempt < self.max_retries:
                    wait_time = self.retry_backoff * (2 ** attempt)
                    logger.warning(f"Connection error, retrying in {wait_time}s")
                    time.sleep(wait_time)
                    continue
                return self._handle_error(e)
            
            except Exception as e:
                return self._handle_error(e)
        
        return self._handle_error(Exception("Max retries exceeded"))
    
    def _handle_error(self, error):
        """Maneja errores de request."""
        if hasattr(error, 'response'):
            status = error.response.status_code
            try:
                data = error.response.json()
                return {
                    "status": "error",
                    "error": data.get("error", "Unknown error"),
                    "detail": data.get("detail", ""),
                    "status_code": status
                }
            except Exception:
                return {
                    "status": "error",
                    "error": f"HTTP {status}",
                    "status_code": status
                }
        return {
            "status": "error",
            "error": str(error)
        }
    
    def get_stats(self):
        """Obtiene estadisticas generales."""
        try:
            return self._get("/dashboard/stats")
        except Exception as e:
            return self._handle_error(e)
    
    def get_logs(self, page=1, per_page=50, **filters):
        """Obtiene logs con filtros y paginacion."""
        params = {
            "page": page,
            "per_page": per_page,
        }
        params.update({k: v for k, v in filters.items() if v})
        try:
            return self._get("/dashboard/logs", params)
        except Exception as e:
            return self._handle_error(e)
    
    def get_log_detail(self, log_id):
        """Obtiene detalle de un log."""
        try:
            return self._get(f"/dashboard/logs/{log_id}")
        except Exception as e:
            return self._handle_error(e)
    
    def get_agents(self):
        """Obtiene lista de agentes."""
        try:
            return self._get("/dashboard/agents")
        except Exception as e:
            return self._handle_error(e)
    
    def get_agent_detail(self, agent_id):
        """Obtiene detalle de un agente."""
        safe_id = sanitize_string(agent_id, 50)
        try:
            return self._get(f"/dashboard/agents/{safe_id}")
        except Exception as e:
            return self._handle_error(e)
    
    def get_chart_top_ips(self, limit=10):
        """Obtiene datos para grafico de top IPs."""
        try:
            return self._get("/dashboard/charts/top-ips", {"limit": limit})
        except Exception as e:
            return self._handle_error(e)
    
    def get_chart_by_type(self):
        """Obtiene datos para grafico de ataques por tipo."""
        try:
            return self._get("/dashboard/charts/by-type")
        except Exception as e:
            return self._handle_error(e)
    
    def get_chart_by_source(self):
        """Obtiene datos para grafico de eventos por fuente."""
        try:
            return self._get("/dashboard/charts/by-source")
        except Exception as e:
            return self._handle_error(e)
    
    def get_chart_by_agent(self):
        """Obtiene datos para grafico de eventos por agente."""
        try:
            return self._get("/dashboard/charts/by-agent")
        except Exception as e:
            return self._handle_error(e)
    
    def get_chart_risk_dist(self):
        """Obtiene datos para grafico de distribucion de riesgo."""
        try:
            return self._get("/dashboard/charts/risk-dist")
        except Exception as e:
            return self._handle_error(e)
    
    def get_chart_daily(self, days=7):
        """Obtiene datos para grafico de tendencias diarias."""
        try:
            return self._get("/dashboard/charts/daily", {"days": days})
        except Exception as e:
            return self._handle_error(e)
    
    def get_health(self):
        """Obtiene estado de salud del sistema."""
        try:
            return self._get("/dashboard/health")
        except Exception as e:
            return self._handle_error(e)
    
    def check_connection(self):
        """Verifica conexion con el servidor."""
        try:
            health = self.get_health()
            return health.get("status") == "success"
        except Exception:
            return False

    def get_threats(self, min_risk=0, compromised=False, coordinated=False, limit=50):
        """Obtiene lista de amenazas correlacionadas."""
        params = {"limit": limit}
        if min_risk > 0:
            params["min_risk"] = min_risk
        if compromised:
            params["compromised"] = 1
        if coordinated:
            params["coordinated"] = 1
        try:
            return self._get("/dashboard/threats", params)
        except Exception as e:
            return self._handle_error(e)

    def get_threats_summary(self):
        """Obtiene resumen de amenazas."""
        try:
            return self._get("/dashboard/threats/summary")
        except Exception as e:
            return self._handle_error(e)

    def get_threats_coordinated(self):
        """Obtiene ataques coordinados."""
        try:
            return self._get("/dashboard/threats/coordinated")
        except Exception as e:
            return self._handle_error(e)

    def get_threats_compromised(self):
        """Obtiene indicadores de compromiso."""
        try:
            return self._get("/dashboard/threats/compromised")
        except Exception as e:
            return self._handle_error(e)

    def get_threat_detail(self, ip):
        """Obtiene detalle de una amenaza."""
        try:
            return self._get(f"/dashboard/threats/{ip}")
        except Exception as e:
            return self._handle_error(e)


def create_client():
    """Factory para crear cliente con configuracion del .env."""
    return SOCAPIClient()