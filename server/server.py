# =============================================================================
# SOC Platform - Servidor de Logs de Seguridad
# =============================================================================
#
# Este servidor recibe eventos de seguridad desde los agentes y los almacena
# en una base de datos SQLite. Cuando detecta eventos de alto riesgo, envia
# alertas via Telegram.
#
# ARQUITECTURA MULTI-AGENTE:
# - Soporta multiples agentes en diferentes hosts
# - Cada agente identifica su fuente de logs (auth.log, suricata.log, etc.)
# - El servidor registra el host objetivo (donde esta el agente)
#
# PROTECCION ANTI-FLOODING/DOS:
# - Rate limiting con token bucket (por IP y API key)
# - Cola asincrona para procesamiento de eventos
# - Circuit breaker para Telegram
# - Backpressure con maximo de requests concurrentes
# - Limitacion de tamano de request
#
# Uso:
#   python server/server.py
#
# Endpoints:
#   POST /log      - Recibe eventos de los agentes (requiere X-API-Key)
#   POST /log/batch - Recibe eventos en batch (optimizado para multiples agentes)
#   GET  /agents   - Lista agentes registrados
#   GET  /stats    - Estadisticas generales
#   GET  /health   - Verifica que el servidor este funcionando
#
# Requisitos:
#   - AGENT_API_KEY debe estar configurado en variable de entorno
#
# =============================================================================

import json
import ipaddress
import logging
import os
import time
import threading
import queue
import uuid
import hashlib
import hmac
import re
from functools import wraps
from flask import Flask, request, jsonify, Response

from .config import AGENT_API_KEY, RATE_LIMIT_RPM, SERVER_PORT, MAX_FIELD_LENGTH
from .config import ENABLE_SSL, SSL_CERT_FILE, SSL_KEY_FILE
from .config import get_server_info, validate_server_config, ALERT_THRESHOLD_RISK
from .config import MAX_CONCURRENT_REQUESTS, MAX_REQUEST_SIZE_KB
from .config import EVENT_QUEUE_SIZE, EVENT_BATCH_SIZE, EVENT_BATCH_TIMEOUT
from .config import CIRCUIT_BREAKER_FAILURE_THRESHOLD, CIRCUIT_BREAKER_RECOVERY_TIMEOUT
from .config import RATE_LIMIT_BURST, FLASK_DEBUG
from .config import AGENT_API_SECRET, NONCE_TTL_SECONDS
from .config import DEDUP_WINDOW_MINUTES, MAX_EVENT_AGE_HOURS, ENABLE_RECORRELATION, RECORRELATION_INTERVAL_HOURS
from .db import (
    init_db, insert_log, log_exists, log_exists_compound,
    alert_exists, save_alert,
    register_agent,
    get_all_logs, get_logs_count,
    get_stats_by_ip, get_stats_by_type, get_stats_by_risk,
    get_stats_by_source, get_stats_by_agent, get_stats_by_target_host,
    get_all_agents
)
from .alerts import send_alert
from .dashboard_api import dashboard_bp
from .threat_correlation import init_threat_intel, analyze_event, get_threat_intel
from .threat_correlation import get_threat_summary, correlate_login_after_bruteforce
from .threat_correlation import re_correlate_all_threats, schedule_re_correlation

import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

template_path = os.path.join(os.path.dirname(__file__), "../dashboard/templates")
app = Flask(__name__, 
    template_folder=template_path,
    static_folder="../dashboard/static",
    static_url_path="/static")

logger.info(f"Template folder: {template_path}")

init_db()
init_threat_intel()

if ENABLE_RECORRELATION:
    schedule_re_correlation(app, interval_hours=RECORRELATION_INTERVAL_HOURS)
    logger.info(f"Re-correlation enabled every {RECORRELATION_INTERVAL_HOURS}h")

app.register_blueprint(dashboard_bp, url_prefix='/dashboard')


request_times = {}
token_buckets = {}
bucket_lock = threading.Lock()


correlation_queue = queue.Queue(maxsize=1000)
correlation_worker_running = True


def correlation_worker():
    """Worker asincrono para correlacion de amenazas."""
    logger.info("Correlation worker started")
    while correlation_worker_running:
        try:
            event_data = correlation_queue.get(timeout=1)
            correlation_queue.task_done()
            
            src_ip = event_data.get("src_ip")
            risk = event_data.get("risk", 0)
            agent_id = event_data.get("agent_id")
            attack_type = event_data.get("attack_type", "unknown")
            target_host = event_data.get("target_host")
            severity = event_data.get("severity")
            
            correlation = analyze_event(
                src_ip=src_ip,
                risk=risk,
                agent_id=agent_id,
                attack_type=attack_type,
                target_host=target_host,
                severity=severity
            )
            
            if correlation.get("is_compromised") or correlation.get("alert_level") == "critical":
                logger.critical(f"BREACH DETECTED: IP {src_ip} - {attack_type} - Agent: {agent_id}")
                if not alert_exists(src_ip, 100, agent_id, "BREACH"):
                    _send_telegram_alert({**event_data, "risk": 100, "severity": "CRITICAL", "attack_type": f"BREACH: {attack_type}"})
                    save_alert(src_ip, 100, agent_id, f"BREACH: {attack_type}")
            
            if correlation.get("is_coordinated") and correlation.get("alert_level") == "high":
                logger.warning(f"COORDINATED ATTACK: IP {src_ip} detected by {correlation.get('agent_count', 1)} agents")
                if not alert_exists(src_ip, 80, agent_id, "COORDINATED_ATTACK"):
                    _send_telegram_alert({**event_data, "risk": 80, "severity": "HIGH", "attack_type": "COORDINATED_ATTACK"})
                    save_alert(src_ip, 80, agent_id, "COORDINATED_ATTACK")
                    
        except queue.Empty:
            continue
        except Exception as e:
            logger.error(f"Correlation worker error: {e}")


correlation_thread = threading.Thread(target=correlation_worker, daemon=True)
correlation_thread.start()

from .dashboard_api import stats_refresh_worker, stats_refresh_running

stats_thread = threading.Thread(target=stats_refresh_worker, daemon=True)
stats_thread.start()


AGENT_API_SECRET = AGENT_API_SECRET or ""
NONCE_TTL = NONCE_TTL_SECONDS or 300

nonce_store: dict = {}  # type: ignore[misc]
nonce_lock = threading.Lock()


def generate_nonce():
    """Genera un nonce unico para cada request."""
    timestamp = int(time.time() * 1000)
    random_part = uuid.uuid4().hex[:16]
    return f"{timestamp}-{random_part}"


def check_nonce(nonce):
    """Verifica si un nonce ya fue usado (previene replay attacks)."""
    now = time.time()
    with nonce_lock:
        cleaned: dict = {k: v for k, v in nonce_store.items() if now - v < NONCE_TTL}  # type: ignore
        nonce_store.clear()
        nonce_store.update(cleaned)

        if nonce in nonce_store:
            return False
        nonce_store[nonce] = now
        return True


def generate_signature(method, path, nonce, timestamp, body=b''):
    """Genera firma HMAC-SHA256 para el request."""
    if not AGENT_API_SECRET:
        return ""
    message = f"{method}&{path}&{nonce}&{timestamp}&{body.decode() if body else ''}"
    return hmac.new(
        AGENT_API_SECRET.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()


def validate_signature(nonce, timestamp, signature, method, path, body=b''):
    """Valida la firma del request."""
    if not AGENT_API_SECRET:
        return True
    if not signature:
        return False
    expected = generate_signature(method, path, nonce, timestamp, body)
    return hmac.compare_digest(signature, expected)


def validate_request_security():
    """
    Valida los headers de seguridad del request.
    
    Returns:
        tuple: (is_valid, error_response)
    """
    nonce = request.headers.get("X-Request-ID")
    timestamp = request.headers.get("X-Request-Timestamp")
    signature = request.headers.get("X-Request-Signature")
    
    if not nonce or not timestamp:
        return True, None
    
    try:
        ts = int(timestamp)
        if abs(time.time() - ts) > NONCE_TTL:
            return False, jsonify({"error": "Request timestamp expired"}), 401
    except (ValueError, TypeError):
        return False, jsonify({"error": "Invalid timestamp format"}), 400
    
    if not check_nonce(nonce):
        return False, jsonify({"error": "Nonce already used (possible replay attack)"}), 401
    
    if AGENT_API_SECRET and signature:
        body = b''
        req_method = request.method
        req_path = request.path
        if not validate_signature(nonce, timestamp, signature, req_method, req_path, body):
            return False, jsonify({"error": "Invalid signature"}), 401
    
    return True, None


def add_response_headers(response):
    """Agrega headers de seguridad a la respuesta."""
    nonce = generate_nonce()
    timestamp = int(time.time())
    response.headers["X-Response-Nonce"] = nonce
    response.headers["X-Response-Timestamp"] = str(timestamp)
    if AGENT_API_SECRET:
        body = b''
        signature = generate_signature("POST", request.path, nonce, timestamp, body)
        response.headers["X-Response-Signature"] = signature
    return response


def sanitize_input(value, max_length=100, pattern=None):
    """Sanitiza entrada de usuario."""
    if not value:
        return None
    value = str(value)[:max_length]
    value = re.sub(r'[<>"\';\\&|`$()]', '', value)
    return value.strip()


class CircuitBreaker:
    def __init__(self, failure_threshold=5, recovery_timeout=60):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time = 0
        self.state = "closed"
        self.lock = threading.Lock()

    def record_success(self):
        with self.lock:
            self.failure_count = 0
            self.state = "closed"

    def record_failure(self):
        with self.lock:
            self.failure_count += 1
            self.last_failure_time = time.time()
            if self.failure_count >= self.failure_threshold:
                self.state = "open"
                logger.warning(f"Circuit breaker opened after {self.failure_count} failures")

    def is_open(self):
        with self.lock:
            if self.state == "open":
                if time.time() - self.last_failure_time > self.recovery_timeout:
                    self.state = "half-open"
                    logger.info("Circuit breaker entering half-open state")
                    return False
                return True
            return False

    def get_state(self):
        with self.lock:
            return self.state


telegram_circuit = CircuitBreaker(
    failure_threshold=CIRCUIT_BREAKER_FAILURE_THRESHOLD,
    recovery_timeout=CIRCUIT_BREAKER_RECOVERY_TIMEOUT
)


event_queue = queue.Queue(maxsize=EVENT_QUEUE_SIZE)
active_requests = 0
active_requests_lock = threading.Lock()
request_semaphore = threading.Semaphore(MAX_CONCURRENT_REQUESTS)


def process_event_queue():
    """Hilo background para procesar eventos de la cola."""
    batch = []
    batch_start = time.time()

    while True:
        try:
            if batch:
                elapsed = time.time() - batch_start
                should_process = (len(batch) >= EVENT_BATCH_SIZE) or (elapsed >= EVENT_BATCH_TIMEOUT)
            else:
                should_process = False

            if should_process and batch:
                _process_batch(batch, skip_dedup=True)
                batch = []
                batch_start = time.time()
            else:
                try:
                    event = event_queue.get(timeout=0.1)
                    batch.append(event)
                    if len(batch) >= EVENT_BATCH_SIZE:
                        _process_batch(batch, skip_dedup=True)
                        batch = []
                        batch_start = time.time()
                except queue.Empty:
                    if batch and (time.time() - batch_start) >= EVENT_BATCH_TIMEOUT:
                        _process_batch(batch, skip_dedup=True)
                        batch = []
                        batch_start = time.time()

        except Exception as e:
            logger.error(f"Error processing event queue: {e}")


def _process_batch(batch, skip_dedup=False):
    """Procesa un lote de eventos."""
    logger.info(f"Processing batch of {len(batch)} events (dedup={skip_dedup})")
    for event_data in batch:
        try:
            _process_single_event(event_data, skip_dedup=skip_dedup)
        except Exception as e:
            logger.error(f"Error processing event: {e}")


def _process_single_event(data, skip_dedup=False):
    """Procesa un solo evento.

    Args:
        data: Datos del evento
        skip_dedup: Si True, omite deduplicacion (para batch mode)
    """
    src_ip = data.get("src_ip")
    risk = data.get("risk", 0)
    attack_type = data.get("attack_type", "unknown")
    agent_id = data.get("agent_id")
    target_host = data.get("target_host")
    severity = data.get("severity")
    event_timestamp = data.get("event_time")
    src_port = data.get("src_port")
    protocol = data.get("protocol")

    if not skip_dedup:
        is_duplicate, is_too_old, existing_id = log_exists_compound(
            src_ip, risk, attack_type, agent_id, event_timestamp,
            window_minutes=DEDUP_WINDOW_MINUTES,
            max_age_hours=MAX_EVENT_AGE_HOURS
        )

        if is_too_old:
            logger.warning(f"Event from {event_timestamp} too old - ignoring (max {MAX_EVENT_AGE_HOURS}h)")
            return

        if is_duplicate:
            logger.debug(f"Duplicate event detected: {src_ip}/{attack_type} from {agent_id}")
            return

    insert_log(
        src_ip=src_ip,
        risk=risk,
        agent_id=agent_id,
        attack_type=attack_type,
        event_time=event_timestamp,
        report_time=data.get("report_time"),
        src_port=src_port,
        protocol=protocol,
        target_host=target_host,
        target_port=data.get("target_port"),
        target_service=data.get("target_service"),
        source=data.get("source"),
        severity=severity,
        raw_log=data.get("raw_log"),
        duration=data.get("duration"),
        extra_data=data.get("extra_data")
    )

    if risk >= 15:
        try:
            correlation_queue.put_nowait({
                "src_ip": src_ip,
                "risk": risk,
                "agent_id": agent_id,
                "attack_type": attack_type,
                "target_host": target_host,
                "severity": severity
            })
        except queue.Full:
            logger.warning("Correlation queue full - skipping correlation for event")

    if risk >= ALERT_THRESHOLD_RISK:
        if not alert_exists(src_ip, risk, agent_id, attack_type):
            _send_telegram_alert(data)
            save_alert(src_ip, risk, agent_id, attack_type)


def _send_telegram_alert(data):
    """Encola alerta a Telegram para envío asíncrono."""
    try:
        telegram_alert_queue.put_nowait({
            "src_ip": data.get("src_ip"),
            "risk": data.get("risk", 0),
            "severity": data.get("severity", "LOW"),
            "attack_type": data.get("attack_type", "unknown"),
            "agent_id": data.get("agent_id"),
            "target_host": data.get("target_host"),
            "target_service": data.get("target_service"),
            "source": data.get("source")
        })
        return True
    except queue.Full:
        logger.warning("Telegram alert queue full - skipping alert")
        return False


def telegram_alert_worker():
    """Procesa alertas de Telegram en background."""
    while telegram_alert_thread_running:
        try:
            data = telegram_alert_queue.get(timeout=1)
        except queue.Empty:
            continue

        if telegram_circuit.is_open():
            logger.warning("Circuit breaker open - skipping Telegram alert")
            telegram_alert_queue.task_done()
            continue

        try:
            result = send_alert(
                src_ip=data.get("src_ip"),
                risk=data.get("risk", 0),
                severity=data.get("severity", "LOW"),
                attack_type=data.get("attack_type", "unknown"),
                agent_id=data.get("agent_id"),
                target_host=data.get("target_host"),
                target_service=data.get("target_service"),
                source=data.get("source")
            )
            if result:
                telegram_circuit.record_success()
            else:
                telegram_circuit.record_failure()
        except Exception as e:
            telegram_circuit.record_failure()
            logger.error(f"Error sending Telegram alert: {e}")
        finally:
            telegram_alert_queue.task_done()


telegram_alert_queue = queue.Queue(maxsize=100)
telegram_alert_thread_running = True
telegram_alert_thread = threading.Thread(target=telegram_alert_worker, daemon=True)
telegram_alert_thread.start()

queue_processor_thread = threading.Thread(target=process_event_queue, daemon=True)
queue_processor_thread.start()


def token_bucket_rate_limit(requests_per_minute=None, burst=None):
    """Decorador de rate limiting con token bucket (por IP)."""
    if requests_per_minute is None:
        requests_per_minute = RATE_LIMIT_RPM
    if burst is None:
        burst = RATE_LIMIT_BURST

    refill_rate = requests_per_minute / 60.0

    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            ip = request.remote_addr
            now = time.time()

            with bucket_lock:
                if ip not in token_buckets:
                    token_buckets[ip] = {
                        "tokens": burst,
                        "last_update": now
                    }

                bucket = token_buckets[ip]
                elapsed = now - bucket["last_update"]
                bucket["tokens"] = min(burst, bucket["tokens"] + elapsed * refill_rate)
                bucket["last_update"] = now

                if bucket["tokens"] < 1:
                    logger.warning(f"Token bucket exhausted for {ip}")
                    return jsonify({"error": "Rate limit exceeded", "retry_after": int(1/refill_rate)}), 429

                bucket["tokens"] -= 1

            return f(*args, **kwargs)
        return wrapper
    return decorator


def rate_limit_by_api_key(requests_per_minute=None):
    """Decorador que limita por API key (para multiples agentes)."""
    if requests_per_minute is None:
        requests_per_minute = RATE_LIMIT_RPM

    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            api_key = request.headers.get("X-API-Key")
            identifier = api_key or request.remote_addr
            now = time.time()

            with bucket_lock:
                if identifier not in request_times:
                    request_times[identifier] = []

                request_times[identifier] = [t for t in request_times[identifier] if now - t < 60]

                if len(request_times[identifier]) >= requests_per_minute:
                    logger.warning(f"Rate limit exceeded for {identifier}")
                    return jsonify({"error": "Rate limit exceeded", "retry_after": 60}), 429

                request_times[identifier].append(now)

            return f(*args, **kwargs)
        return wrapper
    return decorator


def check_request_size():
    """Verifica que el tamano del request no exceda el limite."""
    if request.content_length and request.content_length > MAX_REQUEST_SIZE_KB * 1024:
        logger.warning(f"Request too large: {request.content_length} bytes")
        return False
    return True


def acquire_request_slot():
    """Adquiere un slot para procesar el request (backpressure)."""
    if not request_semaphore.acquire(timeout=1):
        logger.warning("Max concurrent requests reached - rejecting request")
        return False

    global active_requests
    with active_requests_lock:
        active_requests += 1

    return True


def release_request_slot():
    """Libera el slot del request."""
    global active_requests
    with active_requests_lock:
        active_requests -= 1
    request_semaphore.release()


def require_agent_auth(f):
    """Decorador que requiere autenticacion via API Key."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        api_key = request.headers.get("X-API-Key")

        if not api_key or api_key != AGENT_API_KEY:
            logger.warning(f"Unauthorized access attempt from {request.remote_addr}")
            return jsonify({"error": "Unauthorized"}), 401

        return f(*args, **kwargs)
    return wrapper


def validate_ip(ip):
    """Valida que una IP tenga un formato valido."""
    if not ip:
        return False, "IP requerida"

    try:
        ipaddress.ip_address(ip)
        return True, None
    except ValueError:
        return False, "Formato de IP invalido"


def validate_input(data):
    """Valida los datos de entrada de un evento."""
    errors = {}

    src_ip = data.get('src_ip') or data.get('ip')
    if src_ip:
        if len(src_ip) > MAX_FIELD_LENGTH['ip']:
            errors['src_ip'] = f"Muy larga (max {MAX_FIELD_LENGTH['ip']})"
        else:
            try:
                ipaddress.ip_address(src_ip)
            except ValueError:
                errors['src_ip'] = "Formato de IP invalido"

    agent_id = data.get('agent_id')
    if not agent_id:
        errors['agent_id'] = "Requerido"
    elif len(agent_id) > MAX_FIELD_LENGTH['agent_id']:
        errors['agent_id'] = f"Muy largo (max {MAX_FIELD_LENGTH['agent_id']})"

    attack_type = data.get('attack_type') or data.get('event_type')
    if attack_type and len(attack_type) > MAX_FIELD_LENGTH['attack_type']:
        errors['attack_type'] = f"Muy largo (max {MAX_FIELD_LENGTH['attack_type']})"

    source = data.get('source')
    if source and len(source) > MAX_FIELD_LENGTH['source']:
        errors['source'] = f"Muy largo (max {MAX_FIELD_LENGTH['source']})"

    risk = data.get('risk')
    if risk is not None:
        try:
            risk_int = int(risk)
            if risk_int < 0 or risk_int > 1000:
                errors['risk'] = "Valor fuera de rango (0-1000)"
        except (ValueError, TypeError):
            errors['risk'] = "Debe ser un numero"

    return errors


def determine_severity(risk):
    """Determina la severidad basado en el nivel de riesgo."""
    if risk >= 50:
        return "CRITICAL"
    elif risk >= 30:
        return "HIGH"
    elif risk >= 15:
        return "MEDIUM"
    return "LOW"


@app.route("/log", methods=["POST"])
@token_bucket_rate_limit()
@rate_limit_by_api_key()
@require_agent_auth
def log():
    """Endpoint principal para recibir eventos de seguridad."""
    try:
        is_valid, error_resp = validate_request_security()
        if not is_valid:
            return error_resp

        if not acquire_request_slot():
            return add_response_headers(jsonify({"error": "Server overloaded, try later"})), 503

        if not check_request_size():
            return add_response_headers(jsonify({"error": f"Request too large (max {MAX_REQUEST_SIZE_KB}KB)"})), 413

        if request.content_type != "application/json":
            return add_response_headers(jsonify({"error": "Content-Type debe ser application/json"})), 415

        data = request.get_json(silent=True) or {}

        input_errors = validate_input(data)
        if input_errors:
            return add_response_headers(jsonify({"error": "Datos invalidos", "details": input_errors})), 400

        agent_id = data.get("agent_id")
        src_ip = data.get("src_ip") or data.get("ip")
        risk = data.get("risk") or data.get("risk_score") or 0

        if src_ip:
            valid_ip, ip_error = validate_ip(src_ip)
            if not valid_ip:
                return jsonify({"error": ip_error}), 400

        try:
            risk = int(risk)
        except (ValueError, TypeError):
            risk = 0

        attack_type = data.get("attack_type") or data.get("event_type") or "unknown"
        event_time = data.get("event_time")
        report_time = data.get("report_time") or time.strftime("%Y-%m-%d %H:%M:%S") + f".{int(time.time() * 1000) % 1000:03d}"
        src_port = data.get("src_port")
        protocol = data.get("protocol")
        target_host = data.get("target_host")
        target_port = data.get("target_port")
        target_service = data.get("target_service")
        source = data.get("source")
        duration = data.get("duration")
        raw_log = data.get("raw_log")

        extra_data = data.get("extra_data")
        if extra_data and isinstance(extra_data, dict):
            extra_data = json.dumps(extra_data)

        severity = determine_severity(risk)

        hostname = data.get("hostname")
        os_info = data.get("os_info")
        metadata = data.get("metadata")

        register_agent(
            agent_id=agent_id,
            hostname=hostname,
            ip_address=target_host,
            os_info=os_info,
            metadata=metadata
        )

        logger.info(
            f"[{agent_id}] {attack_type} from {src_ip} risk={risk} sev={severity} "
            f"target={target_host}:{target_port} source={source}"
        )

        try:
            event_queue.put_nowait({
                "src_ip": src_ip,
                "risk": risk,
                "agent_id": agent_id,
                "attack_type": attack_type,
                "event_time": event_time,
                "report_time": report_time,
                "src_port": src_port,
                "protocol": protocol,
                "target_host": target_host,
                "target_port": target_port,
                "target_service": target_service,
                "source": source,
                "severity": severity,
                "raw_log": raw_log,
                "duration": duration,
                "extra_data": extra_data
            })
        except queue.Full:
            logger.warning("Event queue full - processing synchronously")
            _process_single_event({
                "src_ip": src_ip,
                "risk": risk,
                "agent_id": agent_id,
                "attack_type": attack_type,
                "event_time": event_time,
                "report_time": report_time,
                "src_port": src_port,
                "protocol": protocol,
                "target_host": target_host,
                "target_port": target_port,
                "target_service": target_service,
                "source": source,
                "severity": severity,
                "raw_log": raw_log,
                "duration": duration,
                "extra_data": extra_data
            })

        return add_response_headers(jsonify({"status": "ok"}))
    except Exception as e:
        logger.error(f"Error processing log request: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500
    finally:
        release_request_slot()


@app.route("/log/batch", methods=["POST"])
@token_bucket_rate_limit()
@rate_limit_by_api_key()
@require_agent_auth
def log_batch():
    """Endpoint optimizado para recibir multiples eventos en batch."""
    is_valid, error_resp = validate_request_security()
    if not is_valid:
        return error_resp

    if not acquire_request_slot():
        return add_response_headers(jsonify({"error": "Server overloaded, try later"})), 503

    try:
        if not check_request_size():
            return add_response_headers(jsonify({"error": f"Request too large (max {MAX_REQUEST_SIZE_KB}KB)"})), 413

        if request.content_type != "application/json":
            return add_response_headers(jsonify({"error": "Content-Type debe ser application/json"})), 415

        data = request.get_json(silent=True) or {}
        events = data.get("events", [])

        if not isinstance(events, list):
            return add_response_headers(jsonify({"error": "events debe ser una lista"})), 400

        if len(events) > EVENT_BATCH_SIZE * 2:
            return add_response_headers(jsonify({"error": f"Too many events (max {EVENT_BATCH_SIZE * 2})"})), 400

        accepted = 0
        rejected = 0

        for event in events:
            event_data = event.get("event", {})
            agent_id = event_data.get("agent_id") or data.get("agent_id")

            if not agent_id:
                rejected += 1
                continue

            src_ip = event_data.get("src_ip")
            if src_ip:
                valid_ip, _ = validate_ip(src_ip)
                if not valid_ip:
                    rejected += 1
                    continue

            try:
                risk = int(event_data.get("risk", 0))
            except (ValueError, TypeError):
                risk = 0

            severity = determine_severity(risk)
            extra_data = event_data.get("extra_data")
            if extra_data and isinstance(extra_data, dict):
                extra_data = json.dumps(extra_data)

            register_agent(
                agent_id=agent_id,
                hostname=event_data.get("hostname"),
                ip_address=event_data.get("target_host"),
                os_info=event_data.get("os_info"),
                metadata=event_data.get("metadata")
            )

            try:
                event_queue.put_nowait({
                    "src_ip": src_ip,
                    "risk": risk,
                    "agent_id": agent_id,
                    "attack_type": event_data.get("attack_type", "unknown"),
                    "event_time": event_data.get("event_time"),
                    "report_time": event_data.get("report_time") or time.strftime("%Y-%m-%d %H%M%S.%f"),
                    "src_port": event_data.get("src_port"),
                    "protocol": event_data.get("protocol"),
                    "target_host": event_data.get("target_host"),
                    "target_port": event_data.get("target_port"),
                    "target_service": event_data.get("target_service"),
                    "source": event_data.get("source"),
                    "severity": severity,
                    "raw_log": event_data.get("raw_log"),
                    "duration": event_data.get("duration"),
                    "extra_data": extra_data
                })
                accepted += 1
            except queue.Full:
                rejected += 1

        logger.info(f"Batch received: {accepted} accepted, {rejected} rejected")
        return add_response_headers(jsonify({"status": "ok", "accepted": accepted, "rejected": rejected}))
    finally:
        release_request_slot()


@app.route("/agents", methods=["GET"])
@rate_limit_by_api_key(requests_per_minute=120)
@require_agent_auth
def agents():
    """Lista todos los agentes registrados."""
    agents_list = get_all_agents()
    return add_response_headers(jsonify({
        "agents": [dict(a) for a in agents_list],
        "total": len(agents_list)
    }))


@app.route("/stats", methods=["GET"])
@rate_limit_by_api_key(requests_per_minute=60)
@require_agent_auth
def stats():
    """Obtiene estadisticas generales."""
    stats_by_ip = get_stats_by_ip(10)
    stats_by_type = get_stats_by_type()
    stats_by_risk = get_stats_by_risk()
    stats_by_source = get_stats_by_source()
    stats_by_agent = get_stats_by_agent()
    stats_by_target = get_stats_by_target_host()

    return jsonify({
        "by_ip": [{"ip": r["src_ip"], "count": r["count"]} for r in stats_by_ip],
        "by_type": [{"type": r["attack_type"], "count": r["count"]} for r in stats_by_type],
        "by_risk": [{"risk": r["risk"], "count": r["count"]} for r in stats_by_risk],
        "by_source": [{"source": r["source"], "count": r["count"]} for r in stats_by_source],
        "by_agent": [{"agent": r["agent_id"], "count": r["count"]} for r in stats_by_agent],
        "by_target": [{"target": r["target_host"], "agent": r["agent_id"], "count": r["count"]} for r in stats_by_target],
        "total_logs": get_logs_count()
    })


@app.route("/logs", methods=["GET"])
@rate_limit_by_api_key(requests_per_minute=60)
@require_agent_auth
def logs():
    """Obtiene logs con filtros opcionales."""
    limit = min(request.args.get("limit", 100, type=int), 1000)
    offset = request.args.get("offset", 0, type=int)

    all_logs = get_all_logs(limit, offset)

    return jsonify({
        "logs": [dict(log) for log in all_logs],
        "total": get_logs_count(),
        "limit": limit,
        "offset": offset
    })


@app.route("/health", methods=["GET"])
def health():
    """Endpoint de salud para verificar que el servidor funciona."""
    with active_requests_lock:
        queue_size = event_queue.qsize()

    return jsonify({
        "status": "healthy",
        "active_requests": active_requests,
        "max_concurrent_requests": MAX_CONCURRENT_REQUESTS,
        "queue_size": queue_size,
        "queue_capacity": EVENT_QUEUE_SIZE,
        "circuit_breaker_state": telegram_circuit.get_state(),
        "rate_limit_rpm": RATE_LIMIT_RPM
    })


@app.route("/.well-known/<path:subpath>", methods=["GET", "POST", "PUT", "DELETE"])
def well_known(subpath):
    """Silencia requests de Chrome y otros browsers."""
    return jsonify({"status": "ok"})


@app.route("/metrics", methods=["GET"])
@require_agent_auth
def metrics():
    """Endpoint de metricas para monitoreo."""
    with active_requests_lock:
        queue_size = event_queue.qsize()

    return jsonify({
        "active_requests": active_requests,
        "max_concurrent_requests": MAX_CONCURRENT_REQUESTS,
        "queue_size": queue_size,
        "queue_capacity": EVENT_QUEUE_SIZE,
        "queue_utilization": round(queue_size / EVENT_QUEUE_SIZE * 100, 2) if EVENT_QUEUE_SIZE > 0 else 0,
        "circuit_breaker": telegram_circuit.get_state(),
        "rate_limit_buckets": len(token_buckets),
        "api_key_rate_limits": len(request_times)
    })


@app.errorhandler(500)
def internal_error(e):
    logger.error(f"Internal error: {e}")
    return jsonify({"error": "Internal server error"}), 500


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404


if __name__ == "__main__":
    errors = validate_server_config()
    if errors:
        logger.warning("Advertencias de configuracion:")
        for e in errors:
            logger.warning(f"  - {e}")

    logger.info("=" * 50)
    logger.info("SERVIDOR SOC - Iniciado")
    for key, value in get_server_info().items():
        logger.info(f"  {key}: {value}")
    logger.info("=" * 50)

    if ENABLE_SSL and os.path.exists(SSL_CERT_FILE) and os.path.exists(SSL_KEY_FILE):
        logger.info(f"HTTPS habilitado con certificados: {SSL_CERT_FILE}")
        app.run(
            port=SERVER_PORT,
            host="0.0.0.0",
            ssl_context=(SSL_CERT_FILE, SSL_KEY_FILE),
            debug=FLASK_DEBUG
        )
    else:
        logger.warning("SSL deshabilitado - usando HTTP insecure")
        app.run(port=SERVER_PORT, host="0.0.0.0", debug=FLASK_DEBUG)
