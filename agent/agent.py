"""
Agente de monitoreo de logs de seguridad.

Este script monitorea archivos de log y detecta patrones de ataques.

FUNCIONALIDADES:
- Monitoreo de multiples fuentes de log (auth.log, iptables, suricata)
- Persistencia de estado entre ejecuciones
- Deduplicacion de logs por hash
- Deteccion inteligente de ataques (batching)
- Eventos para ataques unicos criticos
- Reporte al servidor central con informacion completa
- Batching de eventos para reducir carga en servidor
- Cola de reintentos con exponential backoff
- Proteccion contra flooding del servidor
- Sanitizacion de datos para prevenir log injection
- Validacion de rutas para prevenir path traversal
- Request signing con HMAC-SHA256
- Nonce + Timestamp para prevenir replay attacks

Uso:
    python agent/agent.py
"""
import json
import logging
import os
import platform
import socket
import time
import threading
import queue
import uuid
import hashlib
import hmac
from datetime import datetime, timedelta

import requests

from .config import AGENT_ID, TARGET_HOST, TARGET_SERVICE, SOURCE, SERVER_URL
from .config import BATCH_URL, X_API_KEY, X_API_KEY_SECRET, LOG_FILE, AGENT_INTERVAL
from .config import DETECTION_THRESHOLDS, SEND_COOLDOWN, REQUEST_TIMEOUT
from .config import VERIFY_SSL, get_agent_info, validate_agent_config
from .config import USE_BATCH_MODE, BATCH_SIZE, BATCH_TIMEOUT
from .config import BATCH_RETRY_QUEUE_SIZE, MAX_BATCH_RETRIES
from .config import INITIAL_RETRY_DELAY, MAX_RETRY_DELAY
from .config import MAX_CONSECUTIVE_FAILURES, BACKOFF_MULTIPLIER
from .patterns import (
    get_patterns_for_source, determine_severity,
    extract_timestamp_from_log, format_log_timestamp
)
from .persistence import AgentState
from .security import (
    sanitize_log_string,
    sanitize_raw_log,
    sanitize_ip_address,
    sanitize_user,
    sanitize_extra_data,
)


def _generate_nonce():
    """Genera un nonce unico para cada request."""
    timestamp = int(time.time() * 1000)
    random_part = uuid.uuid4().hex[:16]
    return f"{timestamp}-{random_part}"


def _generate_signature(method, path, nonce, timestamp, body=b''):
    """Genera firma HMAC-SHA256."""
    if not X_API_KEY_SECRET:
        return ""
    message = f"{method}&{path}&{nonce}&{timestamp}&{body.decode() if body else ''}"
    return hmac.new(
        X_API_KEY_SECRET.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()


def _validate_response(nonce, timestamp, signature, method, path, body=b''):
    """Valida la firma de la respuesta."""
    if not X_API_KEY_SECRET:
        return True
    if not signature:
        return False
    expected = _generate_signature(method, path, nonce, timestamp, body)
    return hmac.compare_digest(signature, expected)


logging.basicConfig(
    level=getattr(logging, os.environ.get("AGENT_LOG_LEVEL", "INFO"))
)
logger = logging.getLogger(__name__)

security_logger = logging.getLogger("security")
security_handler = logging.StreamHandler()
security_handler.setFormatter(logging.Formatter(
    '%(levelname)s:agent: %(message)s'
))
security_logger.addHandler(security_handler)
security_logger.setLevel(logging.WARNING)
security_logger.propagate = False

state = AgentState(AGENT_ID)

event_batch = []
batch_lock = threading.Lock()
batch_last_sent = time.time()

retry_queue = queue.Queue(maxsize=BATCH_RETRY_QUEUE_SIZE)
consecutive_failures = 0
failure_lock = threading.Lock()
current_backoff = INITIAL_RETRY_DELAY

retry_thread = None
retry_thread_running = True


def get_system_info():
    """Obtiene informacion del sistema operativo."""
    return {
        "os": platform.system(),
        "os_version": platform.version(),
        "hostname": socket.gethostname(),
        "platform": platform.platform()
    }


def _send_to_server(data, is_retry=False):
    """Funcion interna para enviar datos al servidor con firmas de seguridad."""
    global consecutive_failures, current_backoff

    nonce = _generate_nonce()
    timestamp = int(time.time())
    body = json.dumps(data).encode()

    headers = {
        "X-API-Key": X_API_KEY or "",
        "Content-Type": "application/json",
        "X-Request-ID": nonce,
        "X-Request-Timestamp": str(timestamp),
    }

    if X_API_KEY_SECRET:
        signature = _generate_signature("POST", "/log", nonce, timestamp, body)
        headers["X-Request-Signature"] = signature

    try:
        response = requests.post(
            SERVER_URL,
            json=data,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
            verify=VERIFY_SSL
        )

        if response.status_code == 429:
            logger.warning(f"[{AGENT_ID}] Rate limited by server")
            return False, "rate_limited"

        if response.status_code == 503:
            logger.warning(f"[{AGENT_ID}] Server overloaded")
            return False, "overloaded"

        response.raise_for_status()

        if X_API_KEY_SECRET:
            resp_nonce = response.headers.get("X-Response-Nonce")
            resp_timestamp = response.headers.get("X-Response-Timestamp")
            resp_signature = response.headers.get("X-Response-Signature")
            
            if resp_timestamp:
                time_diff = abs(time.time() - int(resp_timestamp))
                if time_diff > 300:
                    logger.warning(f"[{AGENT_ID}] Response too old")
                    return False, "invalid_response"
            
            if not _validate_response(resp_nonce, resp_timestamp, resp_signature, "POST", "/log", body):
                logger.warning(f"[{AGENT_ID}] Invalid response signature")
                return False, "invalid_signature"

        with failure_lock:
            consecutive_failures = 0
            current_backoff = INITIAL_RETRY_DELAY

        return True, None

    except requests.exceptions.Timeout:
        logger.error(f"[{AGENT_ID}] Request timeout")
        return False, "timeout"
    except requests.exceptions.ConnectionError:
        logger.error(f"[{AGENT_ID}] Server not reachable")
        return False, "connection_error"
    except requests.exceptions.HTTPError as e:
        if e.response and e.response.status_code >= 500:
            logger.error(f"[{AGENT_ID}] Server error: {e}")
            return False, "server_error"
        logger.error(f"[{AGENT_ID}] HTTP error: {e}")
        return False, "http_error"
    except Exception as e:
        logger.error(f"[{AGENT_ID}] Error: {e}")
        return False, "unknown"


def _handle_failure(success, error_type, data):
    """Maneja fallos de envio con backoff."""
    global consecutive_failures, current_backoff

    if success:
        return

    with failure_lock:
        consecutive_failures += 1

        if consecutive_failures > 1:
            current_backoff = min(current_backoff * BACKOFF_MULTIPLIER, MAX_RETRY_DELAY)
        else:
            current_backoff = INITIAL_RETRY_DELAY

        if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
            msg = (f"[{AGENT_ID}] Too many failures ({consecutive_failures}), "
                   f"increasing backoff to {current_backoff}s")
            logger.warning(msg)
            return

    if data and not isinstance(data, dict):
        return

    try:
        retry_queue.put_nowait({
            "data": data,
            "retry_count": 0,
            "last_attempt": time.time()
        })
        logger.debug(f"[{AGENT_ID}] Event queued for retry")
    except queue.Full:
        logger.warning(f"[{AGENT_ID}] Retry queue full, dropping event")


def send_event(data):
    """Envia un evento al servidor central."""
    state.update_stats("events_sent")
    attack = data.get('attack_type', 'unknown')
    src_ip = data.get('src_ip', 'unknown')
    logger.info(f"[{AGENT_ID}] Sent: {attack} from {src_ip}")

    success, error_type = _send_to_server(data)

    transient_errors = ("rate_limited", "overloaded", "timeout", "connection_error")
    if not success and error_type in transient_errors:
        _handle_failure(False, error_type, data)


def send_event_async(data):
    """Envia un evento de manera asincrona (batching)."""
    global event_batch, batch_last_sent

    with batch_lock:
        event_batch.append(data)

        should_send_batch = (
            len(event_batch) >= BATCH_SIZE or
            (time.time() - batch_last_sent) >= BATCH_TIMEOUT
        )

        if should_send_batch and event_batch:
            _send_batch(event_batch.copy())
            event_batch = []
            batch_last_sent = time.time()


def _send_batch(batch):
    """Envia un lote de eventos al servidor."""
    if not batch:
        return

    logger.info(f"[{AGENT_ID}] Sending batch of {len(batch)} events")

    payload = {
        "events": [{"event": event} for event in batch]
    }

    try:
        response = requests.post(
            BATCH_URL,
            json=payload,
            headers={"X-API-Key": X_API_KEY},
            timeout=REQUEST_TIMEOUT,
            verify=VERIFY_SSL
        )

        if response.status_code == 429:
            logger.warning(f"[{AGENT_ID}] Rate limited by server")
            return False, "rate_limited"

        if response.status_code == 503:
            logger.warning(f"[{AGENT_ID}] Server overloaded")
            return False, "overloaded"

        response.raise_for_status()

        for event in batch:
            state.update_stats("events_sent")
            attack = event.get('attack_type', 'unknown')
            src_ip = event.get('src_ip', 'unknown')
            logger.info(f"[{AGENT_ID}] Sent: {attack} from {src_ip}")

        return True, None

    except requests.exceptions.Timeout:
        logger.error(f"[{AGENT_ID}] Batch timeout")
        return False, "timeout"
    except requests.exceptions.ConnectionError:
        logger.error(f"[{AGENT_ID}] Server not reachable")
        return False, "connection_error"
    except requests.exceptions.HTTPError as e:
        if e.response and e.response.status_code >= 500:
            logger.error(f"[{AGENT_ID}] Server error: {e}")
            return False, "server_error"
        logger.error(f"[{AGENT_ID}] HTTP error: {e}")
        return False, "http_error"
    except Exception as e:
        logger.error(f"[{AGENT_ID}] Error: {e}")
        return False, "unknown"


def flush_batch():
    """Fuerza el envio del batch actual."""
    global event_batch, batch_last_sent

    with batch_lock:
        if event_batch:
            _send_batch(event_batch.copy())
            event_batch = []
            batch_last_sent = time.time()


def retry_worker():
    """Hilo worker para procesar eventos en la cola de reintentos."""
    global retry_thread_running, current_backoff

    while retry_thread_running:
        try:
            item = retry_queue.get(timeout=1)

            if item["retry_count"] >= MAX_BATCH_RETRIES:
                logger.warning(f"[{AGENT_ID}] Max retries reached, dropping event")
                retry_queue.task_done()
                continue

            time_since_last = time.time() - item["last_attempt"]
            if time_since_last < current_backoff:
                remaining = current_backoff - time_since_last
                time.sleep(min(remaining, 5))

            if not retry_thread_running:
                retry_queue.task_done()
                continue

            success, _ = _send_to_server(item["data"], is_retry=True)

            if success:
                state.update_stats("events_sent")
                logger.info(f"[{AGENT_ID}] Retry successful: {item['data'].get('attack_type')}")
                retry_queue.task_done()
            else:
                item["retry_count"] += 1
                item["last_attempt"] = time.time()

                with failure_lock:
                    if consecutive_failures < MAX_CONSECUTIVE_FAILURES:
                        try:
                            retry_queue.put_nowait(item)
                        except queue.Full:
                            logger.warning(f"[{AGENT_ID}] Retry queue full, dropping event")

                retry_queue.task_done()

        except queue.Empty:
            continue
        except Exception as e:
            logger.error(f"[{AGENT_ID}] Retry worker error: {e}")

        time.sleep(0.1)


def start_retry_worker():
    """Inicia el hilo de reintentos."""
    global retry_thread, retry_thread_running

    if retry_thread is None or not retry_thread.is_alive():
        retry_thread_running = True
        retry_thread = threading.Thread(target=retry_worker, daemon=True)
        retry_thread.start()
        logger.info(f"[{AGENT_ID}] Retry worker started")


def stop_retry_worker():
    """Detiene el hilo de reintentos."""
    global retry_thread_running

    retry_thread_running = False
    if retry_thread:
        retry_thread.join(timeout=5)


def build_event(attack_type, src_ip, risk=0, src_port=None, dst_port=None,
                user=None, match_data=None, duration=0, attempts_count=0,
                extra_data=None, log_timestamp=None):
    """Construye el payload del evento con datos sanitizados."""
    event_time = log_timestamp if log_timestamp else datetime.now()

    safe_ip = sanitize_ip_address(src_ip) or "unknown"
    safe_user = sanitize_user(user)

    extra = sanitize_extra_data(extra_data) if extra_data else {}
    extra["system_info"] = get_system_info()
    if safe_user:
        extra["user"] = safe_user
    if attempts_count > 0:
        extra["attempts_count"] = attempts_count
    if duration > 0:
        extra["attack_duration_seconds"] = duration

    safe_attack_type = sanitize_log_string(attack_type, 64)

    return {
        "agent_id": AGENT_ID,
        "target_host": sanitize_log_string(TARGET_HOST, 256),
        "target_service": sanitize_log_string(TARGET_SERVICE, 64),
        "src_ip": safe_ip,
        "src_port": src_port,
        "risk": risk,
        "severity": determine_severity(risk),
        "attack_type": safe_attack_type,
        "source": sanitize_log_string(SOURCE, 64),
        "event_time": format_log_timestamp(event_time),
        "report_time": datetime.now().isoformat(),
        "duration": duration,
        "raw_log": sanitize_raw_log(match_data, 1024),
        "extra_data": json.dumps(sanitize_extra_data(extra))
    }


def should_send(ip, event_type, severity="default"):
    """Determina si se debe enviar una alerta basado en cooldown."""
    cooldown_seconds = SEND_COOLDOWN.get(severity.lower(), SEND_COOLDOWN["default"])
    return state.should_send(ip, event_type, severity, cooldown_seconds)


def handle_ssh_brute_force(src_ip, src_port, user, match_data, now, log_timestamp=None):
    """Maneja deteccion de fuerza bruta SSH con batching."""
    safe_ip = sanitize_ip_address(src_ip) or src_ip
    safe_user = sanitize_user(user)
    safe_log = sanitize_raw_log(match_data)

    attempts = state.update_attempts(
        safe_ip,
        now.isoformat(),
        {"port": src_port, "user": safe_user, "log": safe_log}
    )

    log_ts = log_timestamp.isoformat() if log_timestamp else now.isoformat()
    state.record_ip_event(safe_ip, "ssh_brute_force", log_ts)

    threshold = DETECTION_THRESHOLDS["brute_force_attempts"]
    attack_data = state.get_attack_state(safe_ip)

    if len(attempts) >= threshold and not attack_data:
        attack_data = {
            "start_time": now.isoformat(),
            "last_seen": now.isoformat(),
            "event_type": "brute_force_start",
            "attempts_count": len(attempts),
            "users_targeted": list(set(
                sanitize_user(a.get("data", {}).get("user"))
                for a in attempts
                if a.get("data", {}).get("user")
            ))
        }
        state.set_attack_state(safe_ip, attack_data)

        log_ts = log_timestamp.isoformat() if log_timestamp else now.isoformat()
        state.record_ip_event(safe_ip, "brute_force_start", log_ts)
        state.save()

        if should_send(safe_ip, "brute_force_start", "HIGH"):
            risk = 40
            msg = (f"[{AGENT_ID}] CRITICAL: BRUTE FORCE START from {safe_ip} "
                   f"({len(attempts)} attempts)")
            security_logger.warning(msg)
            users = attack_data["users_targeted"]
            target_users = ", ".join(users[:3]) if users else None
            event = build_event(
                "brute_force_start",
                safe_ip, risk,
                src_port=src_port,
                user=target_users,
                match_data=match_data,
                attempts_count=len(attempts),
                log_timestamp=log_timestamp
            )
            if USE_BATCH_MODE:
                send_event_async(event)
            else:
                send_event(event)

    elif attack_data:
        attack_data["last_seen"] = now.isoformat()
        attack_data["attempts_count"] = len(attempts)
        state.set_attack_state(src_ip, attack_data)
        state.save()

        threshold_reached = len(attempts) >= threshold * 2
        if threshold_reached and should_send(src_ip, "brute_force_ongoing", "HIGH"):
            risk = 60
            msg = f"[{AGENT_ID}] CRITICAL: BRUTE FORCE ONGOING from {src_ip} ({len(attempts)} attempts)"
            security_logger.warning(msg)
            event = build_event(
                "brute_force_ongoing",
                src_ip, risk,
                src_port=src_port,
                match_data=match_data,
                attempts_count=len(attempts),
                log_timestamp=log_timestamp
            )
            if USE_BATCH_MODE:
                send_event_async(event)
            else:
                send_event(event)


def handle_ssh_success(src_ip, src_port, user, match_data, now, log_timestamp=None):
    """Maneja inicio de sesion SSH exitoso con correlacion de eventos.

    Segun NIST/MITRE ATT&CK T1078 - Valid Accounts:
    - Un login exitoso es critico si hubo brute force previo de la misma IP
    - El riesgo se calcula en base al contexto historico
    """
    attack_data = state.get_attack_state(src_ip)
    duration = 0
    attempts_count = 0

    if attack_data:
        try:
            start_time = datetime.fromisoformat(attack_data["start_time"])
            duration = int((now - start_time).total_seconds())
        except (ValueError, KeyError):
            duration = 0
        attempts_count = attack_data.get("attempts_count", 0)

    log_ts = log_timestamp.isoformat() if log_timestamp else now.isoformat()
    state.record_ip_event(src_ip, "ssh_login_success", log_ts)

    correlation_risk, correlation_context = state.correlate_ssh_login(src_ip, user)

    correlation_context["duration_seconds"] = duration
    correlation_context["attempts_before_login"] = attempts_count
    correlation_context["attack_active"] = attack_data is not None

    if correlation_context["has_brute_force"] or correlation_context["attack_active"]:
        severity = "CRITICAL"
        risk = 100
    elif correlation_context["has_failed_attempts"]:
        severity = "HIGH"
        risk = min(50 + (correlation_context['failed_attempt_count'] * 5), 80)
    else:
        severity = "MEDIUM"
        risk = 20

    if should_send(src_ip, "ssh_login_success", severity):
        state.update_stats("unique_events")

        if correlation_context["has_brute_force"] or correlation_context["attack_active"]:
            event_type = "ssh_login_success_after_bruteforce"
            bf_count = correlation_context.get('brute_force_count', attempts_count)
            msg = (f"[{AGENT_ID}] CRITICAL: SSH login SUCCESS from {src_ip} "
                   f"AFTER BRUTE FORCE ({bf_count} attempts)")
            security_logger.warning(msg)
        elif correlation_context["has_failed_attempts"]:
            event_type = "ssh_login_success"
            fa_count = correlation_context['failed_attempt_count']
            msg = (f"[{AGENT_ID}] HIGH: SSH login SUCCESS from {src_ip} "
                   f"after {fa_count} failed attempts")
            logger.warning(msg)
        else:
            event_type = "ssh_login_success"
            msg = f"[{AGENT_ID}] MEDIUM: SSH login SUCCESS from {src_ip}"
            logger.info(msg)

        event = build_event(
            event_type,
            src_ip, risk,
            src_port=src_port,
            user=user,
            match_data=match_data,
            duration=duration,
            attempts_count=attempts_count,
            log_timestamp=log_timestamp,
            extra_data={"correlation": correlation_context}
        )
        if USE_BATCH_MODE:
            send_event_async(event)
        else:
            send_event(event)

    state.remove_attack_state(src_ip)
    state.clear_attempts(src_ip)
    state.save()


def handle_connection_closed(src_ip, src_port, match_data, now, log_timestamp=None):
    """Maneja cierre de conexion SSH."""
    attack_data = state.get_attack_state(src_ip)

    if not attack_data:
        return

    try:
        last_seen = datetime.fromisoformat(attack_data["last_seen"])
        window = DETECTION_THRESHOLDS["brute_force_window_seconds"]
        if (now - last_seen).total_seconds() <= window:
            return
    except (ValueError, KeyError):
        pass

    try:
        start_time = datetime.fromisoformat(attack_data["start_time"])
        duration = int((now - start_time).total_seconds())
    except (ValueError, KeyError):
        duration = 0

    if should_send(src_ip, "brute_force_end", "LOW"):
        logger.info(f"[{AGENT_ID}] BRUTE FORCE END {src_ip} duration={duration}s")
        event = build_event(
            "brute_force_end",
            src_ip, -5,
            match_data=match_data,
            duration=duration,
            attempts_count=attack_data.get("attempts_count", 0),
            log_timestamp=log_timestamp
        )
        if USE_BATCH_MODE:
            send_event_async(event)
        else:
            send_event(event)

    state.remove_attack_state(src_ip)


def handle_ssh_timeout(src_ip, src_port, match_data, now, log_timestamp=None):
    """Maneja timeout de autenticacion SSH."""
    attack_data = state.get_attack_state(src_ip)

    if not attack_data:
        if should_send(src_ip, "ssh_timeout_single", "MEDIUM"):
            state.update_stats("unique_events")
            logger.info(f"[{AGENT_ID}] SSH TIMEOUT from {src_ip}")
            event = build_event(
                "ssh_timeout",
                src_ip, 5,
                src_port=src_port,
                match_data=match_data,
                log_timestamp=log_timestamp
            )
            if USE_BATCH_MODE:
                send_event_async(event)
            else:
                send_event(event)
        return

    try:
        last_seen = datetime.fromisoformat(attack_data["last_seen"])
        window = DETECTION_THRESHOLDS["brute_force_window_seconds"]
        if (now - last_seen).total_seconds() <= window:
            return
    except (ValueError, KeyError):
        pass

    try:
        start_time = datetime.fromisoformat(attack_data["start_time"])
        duration = int((now - start_time).total_seconds())
    except (ValueError, KeyError):
        duration = 0

    if should_send(src_ip, "brute_force_timeout", "MEDIUM"):
        logger.info(f"[{AGENT_ID}] BRUTE FORCE TIMEOUT {src_ip}")
        event = build_event(
            "brute_force_timeout",
            src_ip, 0,
            match_data=match_data,
            duration=duration,
            attempts_count=attack_data.get("attempts_count", 0),
            log_timestamp=log_timestamp
        )
        if USE_BATCH_MODE:
            send_event_async(event)
        else:
            send_event(event)

    state.remove_attack_state(src_ip)


def handle_sudo_failure(src_ip, user, match_data, now, log_timestamp=None):
    """Maneja fallos de sudo - evento unico critico."""
    if should_send(src_ip, "sudo_failure", "HIGH"):
        state.update_stats("unique_events")
        logger.warning(f"[{AGENT_ID}] SUDO FAILURE from {src_ip} user={user}")
        event = build_event(
            "sudo_failure",
            src_ip, 15,
            user=user,
            match_data=match_data,
            log_timestamp=log_timestamp
        )
        if USE_BATCH_MODE:
            send_event_async(event)
        else:
            send_event(event)


def handle_pam_auth_failure(src_ip, user, match_data, now, log_timestamp=None):
    """Maneja fallos de autenticacion PAM."""
    attempts = state.update_attempts(
        src_ip,
        now.isoformat(),
        {"type": "pam", "user": user}
    )

    if len(attempts) >= DETECTION_THRESHOLDS.get("brute_force_attempts", 10):
        if should_send(src_ip, "pam_brute_force", "HIGH"):
            security_logger.warning(f"[{AGENT_ID}] PAM BRUTE FORCE from {src_ip} ({len(attempts)} attempts)")
            event = build_event(
                "pam_brute_force",
                src_ip, 20,
                user=user,
                match_data=match_data,
                attempts_count=len(attempts),
                log_timestamp=log_timestamp
            )
            if USE_BATCH_MODE:
                send_event_async(event)
            else:
                send_event(event)
    elif len(attempts) == 1:
        if should_send(src_ip, "pam_auth_failure", "MEDIUM"):
            state.update_stats("unique_events")
            logger.info(f"[{AGENT_ID}] PAM AUTH FAILURE from {src_ip} user={user}")
            event = build_event(
                "pam_auth_failure",
                src_ip, 8,
                user=user,
                match_data=match_data,
                log_timestamp=log_timestamp
            )
            if USE_BATCH_MODE:
                send_event_async(event)
            else:
                send_event(event)


def handle_iptables_block(src_ip, dst_ip, protocol, dst_port, match_data, now, log_timestamp=None):
    """Maneja bloques de iptables - reportar si es desde IP peligrosa."""
    dangerous_ips_key = f"dangerous_{src_ip}"
    count = getattr(state, dangerous_ips_key, 0) + 1
    setattr(state, dangerous_ips_key, count)

    if count >= 5 and should_send(src_ip, "iptables_flood", "MEDIUM"):
        logger.warning(f"[{AGENT_ID}] IPTABLES FLOOD from {src_ip} -> {dst_ip}:{dst_port} ({count} blocks)")
        event = build_event(
            "iptables_flood",
            src_ip, 10,
            dst_port=dst_port,
            match_data=match_data,
            attempts_count=count,
            extra_data={"dst_ip": dst_ip, "protocol": protocol},
            log_timestamp=log_timestamp
        )
        if USE_BATCH_MODE:
            send_event_async(event)
        else:
            send_event(event)
        setattr(state, dangerous_ips_key, 0)


def handle_ids_alert(sid, classification, src_ip, dst_ip, src_port, dst_port, match_data, now, log_timestamp=None):
    """Maneja alertas de IDS/Suricata - siempre critico."""
    if should_send(src_ip, f"ids_{sid}", "HIGH"):
        state.update_stats("unique_events")
        security_logger.warning(f"[{AGENT_ID}] IDS ALERT [{sid}] {classification} from {src_ip} -> {dst_ip}:{dst_port}")
        event = build_event(
            "ids_alert",
            src_ip, 20,
            src_port=src_port,
            dst_port=dst_port,
            match_data=match_data,
            extra_data={
                "ids_sid": sid,
                "classification": classification,
                "dst_ip": dst_ip
            },
            log_timestamp=log_timestamp
        )
        if USE_BATCH_MODE:
            send_event_async(event)
        else:
            send_event(event)


def handle_session_event(event_type, user, match_data, now):
    """Maneja eventos de sesion (opened/closed)."""
    if event_type == "session_opened":
        logger.info(f"[{AGENT_ID}] SESSION OPENED for user {user}")
    elif event_type == "session_closed":
        logger.debug(f"[{AGENT_ID}] SESSION CLOSED for user {user}")


def monitor():
    """Funcion principal de monitoreo."""
    if not os.path.exists(LOG_FILE):
        logger.warning(f"[{AGENT_ID}] Archivo no encontrado: {LOG_FILE}")
        return

    try:
        with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(state.get_file_position())
            lines = f.readlines()
            state.set_file_position(f.tell())
    except IOError as e:
        logger.error(f"[{AGENT_ID}] Error leyendo archivo: {e}")
        return

    patterns = get_patterns_for_source(SOURCE)
    now = datetime.now()

    for line in lines:
        state.update_stats("logs_processed")
        line = line.strip()

        if not line:
            continue

        if state.is_processed(line):
            state.update_stats("logs_duplicated")
            logger.debug(f"[{AGENT_ID}] Log duplicado, ignorando")
            continue

        state.mark_processed(line)

        log_timestamp = extract_timestamp_from_log(line)
        matched = False
        for name, config in patterns.items():
            match = config["pattern"].search(line)
            if not match:
                continue

            matched = True
            attack_type = config["type"]

            extract_ip_fn = config.get("extract_ip") or config.get("extract_src_ip")
            extract_port_fn = config.get("extract_port") or config.get("extract_src_port")
            extract_user_fn = config.get("extract_user")

            src_ip = extract_ip_fn(match) if extract_ip_fn else None
            src_port = extract_port_fn(match) if extract_port_fn else None
            user = extract_user_fn(match) if extract_user_fn else None

            if attack_type == "ssh_brute_force":
                handle_ssh_brute_force(src_ip, src_port, user, match, now, log_timestamp)

            elif attack_type == "ssh_login_success":
                handle_ssh_success(src_ip, src_port, user, match, now, log_timestamp)

            elif attack_type == "ssh_pubkey_success":
                handle_ssh_success(src_ip, src_port, user, match, now, log_timestamp)

            elif attack_type == "ssh_connection_closed":
                handle_connection_closed(src_ip, src_port, match, now, log_timestamp)

            elif attack_type == "ssh_timeout":
                handle_ssh_timeout(src_ip, src_port, match, now, log_timestamp)

            elif attack_type == "ssh_invalid_user":
                handle_ssh_brute_force(src_ip, src_port, user, match, now, log_timestamp)

            elif attack_type == "ssh_max_attempts":
                handle_ssh_brute_force(src_ip, src_port, user, match, now, log_timestamp)

            elif attack_type == "sudo_failure":
                handle_sudo_failure(src_ip, user, match, now, log_timestamp)

            elif attack_type == "pam_auth_failure":
                handle_pam_auth_failure(src_ip, user, match, now, log_timestamp)

            elif attack_type == "session_opened" or attack_type == "session_closed":
                handle_session_event(attack_type, user, match, now)

            elif attack_type == "iptables_blocked":
                dst_ip_fn = config.get("extract_dst_ip")
                proto_fn = config.get("extract_protocol")
                dst_port_fn = config.get("extract_dst_port")
                handle_iptables_block(
                    src_ip,
                    dst_ip_fn(match) if dst_ip_fn else None,
                    proto_fn(match) if proto_fn else None,
                    dst_port_fn(match) if dst_port_fn else None,
                    match, now, log_timestamp
                )

            elif attack_type == "iptables_drop":
                handle_iptables_block(src_ip, None, None, None, match, now, log_timestamp)

            elif attack_type == "ids_alert":
                sid_fn = config.get("extract_sid")
                class_fn = config.get("extract_class")
                dst_ip_fn = config.get("extract_dst_ip")
                dst_port_fn = config.get("extract_dst_port")
                handle_ids_alert(
                    sid_fn(match) if sid_fn else None,
                    class_fn(match) if class_fn else None,
                    src_ip,
                    dst_ip_fn(match) if dst_ip_fn else None,
                    src_port,
                    dst_port_fn(match) if dst_port_fn else None,
                    match, now, log_timestamp
                )

            elif attack_type == "ids_stream":
                if should_send(src_ip, "ids_stream", "MEDIUM"):
                    logger.warning(f"[{AGENT_ID}] IDS STREAM from {src_ip}")
                    event = build_event(
                        "ids_stream",
                        src_ip, 10,
                        match_data=match,
                        log_timestamp=log_timestamp
                    )
                    if USE_BATCH_MODE:
                        send_event_async(event)
                    else:
                        send_event(event)

            break

        if not matched:
            state.update_stats("logs_filtered")

    for src_ip in state.get_all_attack_states():
        attack_data = state.get_attack_state(src_ip)
        if not attack_data:
            continue

        try:
            last_seen = datetime.fromisoformat(attack_data["last_seen"])
            window = DETECTION_THRESHOLDS["brute_force_window_seconds"]
            if now - last_seen > timedelta(seconds=window):
                try:
                    start_time = datetime.fromisoformat(attack_data["start_time"])
                    duration = int((now - start_time).total_seconds())
                except (ValueError, KeyError):
                    duration = 0

                if should_send(src_ip, "brute_force_expired", "LOW"):
                    logger.info(f"[{AGENT_ID}] BRUTE FORCE EXPIRED {src_ip} duration={duration}s")
                    event = build_event(
                        "brute_force_expired",
                        src_ip, 0,
                        duration=duration,
                        attempts_count=attack_data.get("attempts_count", 0)
                    )
                    if USE_BATCH_MODE:
                        send_event_async(event)
                    else:
                        send_event(event)

                state.remove_attack_state(src_ip)
        except (ValueError, KeyError):
            state.remove_attack_state(src_ip)

    state.save()


def main():
    """Punto de entrada principal."""
    global USE_BATCH_MODE

    errors = validate_agent_config()
    if errors:
        logger.error("Errores de configuracion:")
        for e in errors:
            logger.error(f"  - {e}")

    logger.info("=" * 50)
    logger.info("AGENTE SOC - Iniciado")
    for key, value in get_agent_info().items():
        logger.info(f"  {key}: {value}")
    logger.info(f"  Interval: {AGENT_INTERVAL}s")
    logger.info(f"  Batch Mode: {USE_BATCH_MODE}")
    if USE_BATCH_MODE:
        logger.info(f"  Batch Size: {BATCH_SIZE}, Timeout: {BATCH_TIMEOUT}s")
    logger.info("=" * 50)

    logger.info(f"[{AGENT_ID}] Estadisticas actuales: {state.get_stats()}")

    start_retry_worker()

    cycle = 0
    try:
        while True:
            monitor()

            if USE_BATCH_MODE and cycle % 5 == 0:
                flush_batch()

            cycle += 1

            if cycle % 10 == 0:
                stats = state.get_stats()
                retry_q_size = retry_queue.qsize()
                stats_msg = (
                    f"[{AGENT_ID}] Stats: processed={stats['logs_processed']}, "
                    f"duplicated={stats['logs_duplicated']}, "
                    f"filtered={stats['logs_filtered']}, "
                    f"events_sent={stats['events_sent']}, "
                    f"unique_events={stats['unique_events']}, "
                    f"retry_queue={retry_q_size}"
                )
                logger.info(stats_msg)

            time.sleep(AGENT_INTERVAL)
    except KeyboardInterrupt:
        logger.info(f"[{AGENT_ID}] Shutting down...")
    finally:
        flush_batch()
        stop_retry_worker()
        state.save()
        logger.info(f"[{AGENT_ID}] Agent stopped")


if __name__ == "__main__":
    main()
