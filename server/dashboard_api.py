"""
Dashboard API Blueprint - Endpoints de solo lectura para el dashboard.

Proporciona endpoints REST para acceso remoto al dashboard con:
- Autenticacion HTTP Basic
- Rate limiting
- Validacion de inputs
- Audit logging
- Deteccion de amenazas

Uso:
    from dashboard_api import dashboard_bp
    app.register_blueprint(dashboard_bp, url_prefix='/dashboard')
"""

import hashlib
import hmac
import ipaddress
import os
import threading
import re
import time
import uuid
from datetime import datetime
from functools import wraps
from flask import Blueprint, request, jsonify

from .auth import require_auth
from .threat_detector import threat_detector
from .audit import log_error
from .db import (
    get_logs_count, get_all_agents, get_stats_by_source, get_stats_by_agent,
    get_agent_by_id, get_stats_by_ip, get_stats_by_type, get_connection
)
from .threat_correlation import get_threat_intel, get_threat_summary
from .threat_correlation import get_coordinated_attacks, get_compromised_indicators
from .threat_correlation import get_agents_for_ip

dashboard_bp = Blueprint('dashboard', __name__, url_prefix='')  # /dashboard removed for direct access

RATE_LIMIT_PER_MINUTE = int(os.getenv("DASHBOARD_RATE_LIMIT", 100))
RATE_LIMIT_BURST = int(os.getenv("DASHBOARD_RATE_LIMIT_BURST", 20))

dashboard_rate_limit_store = {}
dashboard_rate_lock = __import__('threading').Lock()


STATS_CACHE_TTL = int(os.getenv("DASHBOARD_STATS_CACHE_TTL", 30))
stats_cache = {"data": None, "timestamp": 0}
stats_cache_lock = __import__('threading').Lock()

STATS_REFRESH_INTERVAL = int(os.getenv("DASHBOARD_STATS_REFRESH", 60))
stats_refresh_running = True


def stats_refresh_worker():
    """Worker que recalcula stats periódicamente."""
    import time
    import logging
    
    logger = logging.getLogger(__name__)
    logger.info(f"Stats refresh worker started (interval: {STATS_REFRESH_INTERVAL}s)")
    
    from .db import get_logs_count, get_all_agents
    
    while stats_refresh_running:
        try:
            time.sleep(STATS_REFRESH_INTERVAL)
            
            total_logs = get_logs_count()
            total_agents = len(get_all_agents())
            
            with get_connection() as conn:
                c = conn.cursor()
                c.execute("SELECT COUNT(*) FROM logs WHERE risk >= 15")
                high_risk = c.fetchone()[0]
                c.execute("SELECT COUNT(*) FROM logs WHERE risk >= 50 AND risk < 100")
                critical = c.fetchone()[0]
                c.execute("SELECT COUNT(*) FROM logs WHERE risk >= 100")
                breach = c.fetchone()[0]
                c.execute("SELECT risk FROM logs")
                risks = [row[0] for row in c.fetchall()]
                risk_dist = {
                    "LOW": len([r for r in risks if r < 15]),
                    "MEDIUM": len([r for r in risks if 15 <= r < 30]),
                    "HIGH": len([r for r in risks if 30 <= r < 50]),
                    "CRITICAL": len([r for r in risks if 50 <= r < 100]),
                    "BREACH": len([r for r in risks if r >= 100])
                }
                c.execute("SELECT severity, COUNT(*) FROM logs GROUP BY severity")
                severity_dist = {row[0] or 'UNKNOWN': row[1] for row in c.fetchall()}
            
            stats_data = {
                "total_logs": total_logs,
                "total_agents": total_agents,
                "high_risk_events": high_risk,
                "critical_events": critical,
                "breach_events": breach,
                "risk_distribution": risk_dist,
                "severity_distribution": severity_dist
            }
            
            with stats_cache_lock:
                stats_cache["data"] = stats_data
                stats_cache["timestamp"] = time.time()
                
        except Exception as e:
            logger.error(f"Stats refresh error: {e}")


def get_cached_stats():
    """Obtiene stats con cache."""
    import time
    
    now = time.time()
    with stats_cache_lock:
        if stats_cache["data"] and (now - stats_cache["timestamp"]) < STATS_CACHE_TTL:
            return stats_cache["data"]
        return None


def set_cached_stats(data):
    """Guarda stats en cache."""
    import time
    
    with stats_cache_lock:
        stats_cache["data"] = data
        stats_cache["timestamp"] = time.time()


def dashboard_rate_limit(requests_per_minute=None):
    """Decorador de rate limiting para endpoints del dashboard."""
    if requests_per_minute is None:
        requests_per_minute = RATE_LIMIT_PER_MINUTE

    refill_rate = requests_per_minute / 60.0

    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            ip = request.remote_addr

            if threat_detector.is_blocked(ip):
                return jsonify({
                    "status": "error",
                    "error": "Access denied",
                    "detail": "Your IP has been blocked"
                }), 403

            with dashboard_rate_lock:
                now = __import__('time').time()

                if ip not in dashboard_rate_limit_store:
                    dashboard_rate_limit_store[ip] = {
                        "tokens": RATE_LIMIT_BURST,
                        "last_update": now
                    }

                bucket = dashboard_rate_limit_store[ip]
                elapsed = now - bucket["last_update"]
                bucket["tokens"] = min(RATE_LIMIT_BURST, bucket["tokens"] + elapsed * refill_rate)
                bucket["last_update"] = now

                if bucket["tokens"] < 1:
                    threat_detector.record_rate_limit_violation(ip)
                    log_error("RATE_LIMIT_EXCEEDED", f"IP {ip} exceeded rate limit", ip=ip)
                    return jsonify({
                        "status": "error",
                        "error": "Rate limit exceeded",
                        "retry_after": int(1/refill_rate)
                    }), 429

                bucket["tokens"] -= 1

            result = f(*args, **kwargs)
            
            if DASHBOARD_API_SECRET:
                if hasattr(result, 'headers'):
                    result = add_signature_headers(result)
            
            return result
        return wrapper
    return decorator


def validate_ip(ip):
    """Valida formato de IP."""
    if not ip:
        return True
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def sanitize_string(value, max_length=100):
    """Sanitiza una cadena de texto."""
    if not value:
        return None
    value = str(value)[:max_length]
    value = re.sub(r'[<>\'\";]', '', value)
    return value.strip()


def escape_sql_like(pattern):
    """
    Escapa caracteres especiales en patrones LIKE para prevenir injection.
    
    Los caracteres especiales de LIKE son: % _ \
    """
    if not pattern:
        return None
    pattern = str(pattern)
    pattern = pattern.replace('\\', '\\\\')
    pattern = pattern.replace('%', r'\%')
    pattern = pattern.replace('_', r'\_')
    return pattern


def validate_sql_param(param, param_name="param"):
    """
    Valida que un parametro no contenga patrones dangerous para SQL.
    """
    if not param:
        return True, None
    
    param_str = str(param).lower()
    
    dangerous_patterns = [
        (r'\besql\b', "SQL keyword detected"),
        (r'union\s+select', "UNION SELECT detected"),
        (r';\s*drop', "DROP statement detected"),
        (r';\s*delete', "DELETE statement detected"),
        (r';\s*insert', "INSERT statement detected"),
        (r';\s*update', "UPDATE statement detected"),
        (r'--\s*$', "SQL comment detected"),
        (r'/\*.*\*/', "Block comment detected"),
    ]
    
    for pattern, message in dangerous_patterns:
        if re.search(pattern, param_str):
            return False, f"Invalid {param_name}: {message}"
    
    return True, None


@dashboard_bp.route("/stats", methods=["GET"])
@dashboard_rate_limit(30)
@require_auth
def stats():
    """
    Estadisticas generales del sistema.
    Usa cache para evitar consultas repetitivas.
    
    Returns:
        JSON con totales y distribuciones.
    """
    cached = get_cached_stats()
    if cached:
        return jsonify({
            "status": "success",
            "data": cached,
            "cached": True
        })
    
    total_logs = get_logs_count()
    total_agents = len(get_all_agents())

    c = None
    conn = None
    try:
        from .db import get_connection
        with get_connection() as conn:
            c = conn.cursor()

            c.execute("SELECT COUNT(*) FROM logs WHERE risk >= 15")
            high_risk = c.fetchone()[0]

            c.execute("SELECT COUNT(*) FROM logs WHERE risk >= 50 AND risk < 100")
            critical = c.fetchone()[0]

            c.execute("SELECT COUNT(*) FROM logs WHERE risk >= 100")
            breach = c.fetchone()[0]

            c.execute("""
                SELECT severity, COUNT(*) as count
                FROM logs
                GROUP BY severity
            """)
            severity_dist = {row[0] or 'UNKNOWN': row[1] for row in c.fetchall()}

            c.execute("SELECT risk FROM logs")
            risks = [row[0] for row in c.fetchall()]
            risk_dist = {
                "LOW": len([r for r in risks if r < 15]),
                "MEDIUM": len([r for r in risks if 15 <= r < 30]),
                "HIGH": len([r for r in risks if 30 <= r < 50]),
                "CRITICAL": len([r for r in risks if 50 <= r < 100]),
                "BREACH": len([r for r in risks if r >= 100])
            }
    except Exception:
        high_risk = 0
        critical = 0
        breach = 0
        severity_dist = {}
        risk_dist = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0, "BREACH": 0}

    stats_data = {
        "total_logs": total_logs,
        "total_agents": total_agents,
        "high_risk_events": high_risk,
        "critical_events": critical,
        "breach_events": breach,
        "risk_distribution": risk_dist,
        "severity_distribution": severity_dist
    }
    
    set_cached_stats(stats_data)

    return jsonify({
        "status": "success",
        "data": stats_data
    })


@dashboard_bp.route("/logs", methods=["GET"])
@dashboard_rate_limit(60)
@require_auth
def logs():
    """
    Lista de logs con filtros y paginacion.

    Query params:
        page: Numero de pagina (default 1)
        per_page: Items por pagina (default 50, max 100)
        agent_id: Filtrar por agente
        source: Filtrar por fuente
        min_risk: Filtrar por riesgo minimo
        src_ip: Filtrar por IP origen
        severity: Filtrar por severidad

    Returns:
        JSON con logs y metadatos de paginacion.
    """
    page = max(1, request.args.get("page", 1, type=int))
    per_page = min(100, max(1, request.args.get("per_page", 50, type=int)))
    offset = (page - 1) * per_page

    filters = {}
    if request.args.get("agent_id"):
        filters["agent_id"] = sanitize_string(request.args.get("agent_id"))
    if request.args.get("source"):
        filters["source"] = sanitize_string(request.args.get("source"))
    if request.args.get("min_risk"):
        try:
            val = request.args.get("min_risk")
            filters["min_risk"] = max(0, int(val or 0))
        except (ValueError, TypeError):
            pass
    if request.args.get("src_ip"):
        ip = request.args.get("src_ip")
        if validate_ip(ip):
            filters["src_ip"] = ip
    if request.args.get("severity"):
        filters["severity"] = sanitize_string(request.args.get("severity"), 20)

    query = "SELECT * FROM logs WHERE 1=1"
    params = []

    if filters.get("agent_id"):
        query += " AND agent_id = ?"
        params.append(filters["agent_id"])
    if filters.get("source"):
        query += " AND source = ?"
        params.append(filters["source"])
    if filters.get("min_risk") is not None:
        query += " AND risk >= ?"
        params.append(filters["min_risk"])
    if filters.get("src_ip"):
        escaped = escape_sql_like(filters["src_ip"])
        query += " AND src_ip LIKE ? ESCAPE '\\'"
        params.append(f"%{escaped}%")
    if filters.get("severity"):
        query += " AND severity = ?"
        params.append(filters["severity"])

    count_query = query.replace("SELECT *", "SELECT COUNT(*)")

    try:
        from .db import get_connection
        with get_connection() as conn:
            c = conn.cursor()

            c.execute(count_query, params)
            total = c.fetchone()[0]

            query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            params.extend([per_page, offset])

            c.execute(query, params)
            rows = c.fetchall()
            logs = [dict(row) for row in rows]
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

    total_pages = (total + per_page - 1) // per_page

    return jsonify({
        "status": "success",
        "data": logs,
        "meta": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "total_pages": total_pages,
            "filters": filters
        }
    })


@dashboard_bp.route("/logs/<int:log_id>", methods=["GET"])
@dashboard_rate_limit(60)
@require_auth
def log_detail(log_id):
    """
    Detalle de un log especifico.

    Args:
        log_id: ID del log

    Returns:
        JSON con el detalle del log.
    """
    try:
        from .db import get_connection
        with get_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM logs WHERE id = ?", (log_id,))
            row = c.fetchone()

            if not row:
                return jsonify({"status": "error", "error": "Log not found"}), 404

            return jsonify({
                "status": "success",
                "data": dict(row)
            })
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


@dashboard_bp.route("/agents", methods=["GET"])
@dashboard_rate_limit(30)
@require_auth
def agents():
    """
    Lista de agentes registrados.

    Returns:
        JSON con lista de agentes.
    """
    try:
        from .db import get_connection
        with get_connection() as conn:
            c = conn.cursor()
            c.execute("""
                SELECT
                    a.agent_id,
                    a.hostname,
                    a.ip_address,
                    a.status,
                    a.last_seen,
                    a.os_info,
                    COUNT(l.id) as total_events,
                    MAX(l.risk) as max_risk,
                    MAX(l.timestamp) as last_event
                FROM agents a
                LEFT JOIN logs l ON a.agent_id = l.agent_id
                GROUP BY a.agent_id
                ORDER BY total_events DESC
            """)
            rows = c.fetchall()
            agents_list = [dict(row) for row in rows]

            return jsonify({
                "status": "success",
                "data": agents_list,
                "meta": {"total": len(agents_list)}
            })
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


@dashboard_bp.route("/agents/<agent_id>", methods=["GET"])
@dashboard_rate_limit(30)
@require_auth
def agent_detail(agent_id):
    """
    Detalle de un agente especifico.

    Args:
        agent_id: ID del agente

    Returns:
        JSON con el detalle del agente.
    """
    try:
        agent = get_agent_by_id(sanitize_string(agent_id, 100))
        if not agent:
            return jsonify({"status": "error", "error": "Agent not found"}), 404

        return jsonify({
            "status": "success",
            "data": dict(agent)
        })
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


@dashboard_bp.route("/charts/top-ips", methods=["GET"])
@dashboard_rate_limit(30)
@require_auth
def chart_top_ips():
    """
    Datos para grafico de top IPs atacantes.

    Query params:
        limit: Numero de IPs (default 10)

    Returns:
        JSON con datos para grafico.
    """
    limit = min(50, max(1, request.args.get("limit", 10, type=int)))

    try:
        stats = get_stats_by_ip(limit)
        data = [{"ip": row["src_ip"], "count": row["count"]} for row in stats]

        return jsonify({
            "status": "success",
            "data": data
        })
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


@dashboard_bp.route("/charts/by-type", methods=["GET"])
@dashboard_rate_limit(30)
@require_auth
def chart_by_type():
    """
    Datos para grafico de ataques por tipo.

    Returns:
        JSON con datos para grafico.
    """
    try:
        stats = get_stats_by_type()
        data = [{"type": row["attack_type"], "count": row["count"]} for row in stats]

        return jsonify({
            "status": "success",
            "data": data
        })
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


@dashboard_bp.route("/charts/by-source", methods=["GET"])
@dashboard_rate_limit(30)
@require_auth
def chart_by_source():
    """
    Datos para grafico de eventos por fuente.

    Returns:
        JSON con datos para grafico.
    """
    try:
        stats = get_stats_by_source()
        data = [{"source": row["source"], "count": row["count"]} for row in stats]

        return jsonify({
            "status": "success",
            "data": data
        })
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


@dashboard_bp.route("/charts/by-agent", methods=["GET"])
@dashboard_rate_limit(30)
@require_auth
def chart_by_agent():
    """
    Datos para grafico de eventos por agente.

    Returns:
        JSON con datos para grafico.
    """
    try:
        stats = get_stats_by_agent()
        data = [{"agent": row["agent_id"], "count": row["count"]} for row in stats]

        return jsonify({
            "status": "success",
            "data": data
        })
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


@dashboard_bp.route("/charts/risk-dist", methods=["GET"])
@dashboard_rate_limit(30)
@require_auth
def chart_risk_dist():
    """
    Datos para grafico de distribucion de riesgo.

    Returns:
        JSON con datos para grafico.
    """
    try:
        from .db import get_connection
        with get_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT risk FROM logs")
            risks = [row[0] for row in c.fetchall()]

            data = {
                "Bajo (0-14)": len([r for r in risks if r < 15]),
                "Medio (15-29)": len([r for r in risks if 15 <= r < 30]),
                "Alto (30-49)": len([r for r in risks if 30 <= r < 50]),
                "Critico (50+)": len([r for r in risks if r >= 50])
            }

            return jsonify({
                "status": "success",
                "data": data
            })
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


@dashboard_bp.route("/charts/daily", methods=["GET"])
@dashboard_rate_limit(30)
@require_auth
def chart_daily():
    """
    Datos de eventos por dia para grafico de tendencias.

    Query params:
        days: Numero de dias (default 7, max 30)

    Returns:
        JSON con datos diarios.
    """
    days = min(30, max(1, request.args.get("days", 7, type=int)))

    try:
        from .db import get_connection
        with get_connection() as conn:
            c = conn.cursor()
            c.execute("""
                SELECT DATE(timestamp) as date, COUNT(*) as count
                FROM logs
                WHERE timestamp >= datetime('now', ? || ' days')
                GROUP BY DATE(timestamp)
                ORDER BY date ASC
            """, (-days,))

            data = [{"date": row[0], "count": row[1]} for row in c.fetchall()]

            return jsonify({
                "status": "success",
                "data": data
            })
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


@dashboard_bp.route("/health", methods=["GET"])
def health():
    """
    Estado del sistema para monitoreo.

    Returns:
        JSON con estado de salud.
    """
    try:
        total_logs = get_logs_count()
        total_agents = len(get_all_agents())

        return jsonify({
            "status": "success",
            "data": {
                "healthy": True,
                "total_logs": total_logs,
                "total_agents": total_agents,
                "timestamp": datetime.now().isoformat()
            }
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "data": {
                "healthy": False,
                "error": str(e)
            }
        }), 500


@dashboard_bp.errorhandler(400)
def bad_request(e):
    return jsonify({"status": "error", "error": "Bad request"}), 400


@dashboard_bp.errorhandler(404)
def not_found(e):
    return jsonify({"status": "error", "error": "Not found"}), 404


@dashboard_bp.errorhandler(500)
def internal_error(e):
    return jsonify({"status": "error", "error": "Internal server error"}), 500


DASHBOARD_API_SECRET = os.getenv("DASHBOARD_API_SECRET", "")

nonce_store = {}  # type: ignore
nonce_lock: threading.Lock = __import__('threading').Lock()  # type: ignore
NONCE_TTL = 300


def generate_nonce():
    """Genera un nonce unico."""
    timestamp = int(time.time() * 1000)
    random_part = uuid.uuid4().hex[:16]
    return f"{timestamp}-{random_part}"


def generate_signature(method, path, nonce, timestamp, body=b''):
    """Genera signature HMAC para la respuesta."""
    if not DASHBOARD_API_SECRET:
        return ""
    message = f"{method}&{path}&{nonce}&{timestamp}&{body.decode() if body else ''}"
    return hmac.new(
        DASHBOARD_API_SECRET.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()


def add_signature_headers(response):
    """Agrega headers de firma a la respuesta."""
    nonce = generate_nonce()
    timestamp = int(time.time())
    
    response.headers["X-Response-Nonce"] = nonce
    response.headers["X-Response-Timestamp"] = str(timestamp)
    
    if DASHBOARD_API_SECRET:
        path = request.path
        body = b''
        signature = generate_signature("GET", path, nonce, timestamp, body)
        response.headers["X-Response-Signature"] = signature
    
    return response


def _check_nonce(nonce):
    """Verifica si un nonce ya fue usado."""
    now = time.time()

    with nonce_lock:
        cleaned: dict = {k: v for k, v in nonce_store.items() if now - v < NONCE_TTL}  # type: ignore
        nonce_store.clear()
        nonce_store.update(cleaned)

        if nonce in nonce_store:
            return False

        nonce_store[nonce] = now
        return True


def require_signature(f):
    """Decorador que require firma valida para requests signed."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        nonce = request.headers.get("X-Request-ID")
        timestamp = request.headers.get("X-Request-Timestamp")
        signature = request.headers.get("X-Request-Signature")
        
        if not nonce or not timestamp:
            return jsonify({
                "status": "error",
                "error": "Missing security headers"
            }), 400
        
        try:
            time_diff = abs(time.time() - int(timestamp))
            if time_diff > NONCE_TTL:
                return jsonify({
                    "status": "error",
                    "error": "Request timestamp expired"
                }), 401
        except (ValueError, TypeError):
            return jsonify({
                "status": "error",
                "error": "Invalid timestamp"
            }), 400
        
        if not _check_nonce(nonce):
            return jsonify({
                "status": "error",
                "error": "Nonce already used (possible replay attack)"
            }), 401
        
        if DASHBOARD_API_SECRET and signature:
            body = b''
            expected = generate_signature(
                "GET", request.path, nonce, int(timestamp), body
            )
            if not hmac.compare_digest(signature, expected):
                return jsonify({
                    "status": "error",
                    "error": "Invalid signature"
                }), 401
        
        return f(*args, **kwargs)
    return wrapper


api_key_rate_store = {}
api_key_rate_lock = __import__('threading').Lock()


def rate_limit_by_api_key(requests_per_minute=None):
    """Rate limiting por API key."""
    if requests_per_minute is None:
        requests_per_minute = 60
    
    refill_rate = requests_per_minute / 60.0
    
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            api_key = request.headers.get("X-API-Key") or request.headers.get("Authorization")
            identifier = api_key or request.remote_addr
            now = time.time()
            
            with api_key_rate_lock:
                if identifier not in api_key_rate_store:
                    api_key_rate_store[identifier] = {
                        "tokens": 20,
                        "last_update": now
                    }
                
                bucket = api_key_rate_store[identifier]
                elapsed = now - bucket["last_update"]
                bucket["tokens"] = min(20, bucket["tokens"] + elapsed * refill_rate)
                bucket["last_update"] = now
                
                if bucket["tokens"] < 1:
                    return jsonify({
                        "status": "error",
                        "error": "Rate limit exceeded"
                    }), 429
                
                bucket["tokens"] -= 1
            
            return f(*args, **kwargs)
        return wrapper
    return decorator


# PCAP route removed - server only provides JSON API
# Dashboard (app.py) handles the HTML rendering


@dashboard_bp.route("/threats", methods=["GET"])
@dashboard_rate_limit(30)
@require_auth
def threats():
    """
    Lista de amenazas correlacionadas.
    
    Query params:
        min_risk: Filtrar por riesgo minimo
        compromised: Solo comprometidos (1/0)
        coordinated: Solo coordinados (1/0)
        limit: Limite de resultados (default 50)
    
    Returns:
        JSON con lista de amenazas.
    """
    min_risk = request.args.get("min_risk", 0, type=int)
    compromised_only = request.args.get("compromised", 0, type=int) == 1
    coordinated_only = request.args.get("coordinated", 0, type=int) == 1
    limit = min(100, max(1, request.args.get("limit", 50, type=int)))
    
    try:
        threats_list = get_threat_intel(
            min_risk=min_risk,
            compromised_only=compromised_only,
            coordinated_only=coordinated_only,
            limit=limit
        )
        
        return jsonify({
            "status": "success",
            "data": threats_list,
            "meta": {
                "total": len(threats_list),
                "filters": {
                    "min_risk": min_risk,
                    "compromised_only": compromised_only,
                    "coordinated_only": coordinated_only
                }
            }
        })
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


@dashboard_bp.route("/pcap/detections", methods=["GET"])
def pcap_detections():
    """
    Lista de detecciones PCAP del pcap-analyzer.
    
    Query params:
        min_risk: Filtrar por riesgo minimo
        attack_type: Filtrar por tipo de ataque
        limit: Limite de resultados
    
    Returns:
        JSON con lista de detecciones PCAP.
    """
    min_risk = request.args.get("min_risk", 0, type=int)
    attack_type = request.args.get("attack_type", "")
    limit = min(100, max(1, request.args.get("limit", 50, type=int)))

    try:
        conn = get_connection()
        cursor = conn.cursor()

        query = """
            SELECT id, src_ip, dst_ip, dst_port, risk, attack_type, 
                   severity, report_time, extra_data
            FROM logs
            WHERE source LIKE '%pcap%' OR attack_type LIKE '%download%' OR attack_type LIKE '%flood%'
        """
        params = []

        if min_risk > 0:
            query += " AND risk >= ?"
            params.append(min_risk)

        if attack_type:
            query += " AND attack_type LIKE ?"
            params.append(f"%{attack_type}%")

        query += " ORDER BY report_time DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)
        rows = cursor.fetchall()

        detections = []
        for row in rows:
            extra_data = {}
            if row[8]:
                try:
                    extra_data = json.loads(row[8])
                except:
                    pass

            detections.append({
                "id": row[0],
                "src_ip": row[1],
                "dst_ip": row[2],
                "dst_port": row[3],
                "risk": row[4],
                "attack_type": row[5],
                "severity": row[6],
                "report_time": row[7],
                "pcap_file": extra_data.get("input_file", ""),
                "mitre": extra_data.get("mitre_technique", ""),
                "indicators": extra_data.get("indicators", {}),
                "extra_data": extra_data
            })

        cursor.close()
        conn.close()

        return jsonify({
            "status": "success",
            "data": detections,
            "meta": {
                "total": len(detections),
                "filters": {
                    "min_risk": min_risk,
                    "attack_type": attack_type
                }
            }
        })
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


@dashboard_bp.route("/threats/summary", methods=["GET"])
@dashboard_rate_limit(30)
@require_auth
def threats_summary():
    """
    Resumen de amenazas correlacionadas.
    
    Returns:
        JSON con estadisticas de amenazas.
    """
    try:
        summary = get_threat_summary()
        
        return jsonify({
            "status": "success",
            "data": summary
        })
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


@dashboard_bp.route("/threats/coordinated", methods=["GET"])
@dashboard_rate_limit(30)
@require_auth
def threats_coordinated():
    """
    Lista de ataques coordinados (vistos por multiple agentes).
    
    Returns:
        JSON con ataques coordinados.
    """
    try:
        attacks = get_coordinated_attacks()
        
        return jsonify({
            "status": "success",
            "data": attacks,
            "meta": {"count": len(attacks)}
        })
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


@dashboard_bp.route("/threats/compromised", methods=["GET"])
@dashboard_rate_limit(30)
@require_auth
def threats_compromised():
    """
    Lista de indicadores de compromiso (BREACH).
    
    Returns:
        JSON con compromisos detectados.
    """
    try:
        compromised = get_compromised_indicators()
        
        return jsonify({
            "status": "success",
            "data": compromised,
            "meta": {"count": len(compromised)}
        })
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


@dashboard_bp.route("/threats/<ip>", methods=["GET"])
@dashboard_rate_limit(30)
@require_auth
def threat_detail(ip):
    """
    Detalle de una amenaza especifica.
    
    Args:
        ip: IP de la amenaza
    
    Returns:
        JSON con detalle de la amenaza.
    """
    from .threat_correlation import get_threat_intel
    
    try:
        threats = get_threat_intel(ip=ip, limit=1)
        
        if not threats:
            return jsonify({"status": "error", "error": "Threat not found"}), 404
        
        threat = threats[0]
        
        agents_data = get_agents_for_ip(ip)
        
        return jsonify({
            "status": "success",
            "data": {
                "threat": threat,
                "agents_affected": agents_data
            }
        })
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500
