"""
Base class para agentes SOC.

Proporciona funcionalidad comun: envios, batching, retry, estado, logging.
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
from datetime import datetime
from pathlib import Path
from typing import Optional, Any

import requests


logger = logging.getLogger(__name__)


def generate_nonce():
    """Genera un nonce unico para cada request."""
    timestamp = int(time.time() * 1000)
    random_part = uuid.uuid4().hex[:16]
    return f"{timestamp}-{random_part}"


def generate_signature(method, path, nonce, timestamp, body=b'', secret=''):
    """Genera firma HMAC-SHA256."""
    if not secret:
        return ""
    message = f"{method}&{path}&{nonce}&{timestamp}&{body.decode() if body else ''}"
    return hmac.new(
        secret.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()


def validate_response_signature(nonce, timestamp, signature, method, path, body=b'', secret=''):
    """Valida la firma de la respuesta del servidor."""
    if not secret:
        return True
    if not signature:
        return False
    expected = generate_signature(method, path, nonce, timestamp, body, secret)
    return hmac.compare_digest(signature, expected)


class AgentBase:
    """
    Clase base para agentes de monitoreo.

    Proporciona:
    - Persistencia de estado
    - Envio de eventos (sync y async)
    - Retry con exponential backoff
    - Rate limiting local
    - Deduplicacion
    - Logging estructurado
    """

    def __init__(
        self,
        agent_id: str,
        server_url: str,
        batch_url: str,
        api_key: str,
        log_file: str,
        verify_ssl: bool = True,
        request_timeout: int = 10,
        use_batch_mode: bool = True,
        batch_size: int = 20,
        batch_timeout: int = 30,
        batch_retry_queue_size: int = 100,
        max_batch_retries: int = 3,
        initial_retry_delay: int = 5,
        max_retry_delay: int = 120,
        max_consecutive_failures: int = 10,
        backoff_multiplier: float = 2.0,
        agent_interval: int = 10,
        state_dir: Optional[str] = None,
        api_secret: str = "",
    ):
        self.agent_id = agent_id
        self.server_url = server_url
        self.batch_url = batch_url
        self.api_key = api_key
        self.log_file = log_file
        self.verify_ssl = verify_ssl
        self.request_timeout = request_timeout
        self.api_secret = api_secret
        self.use_batch_mode = use_batch_mode
        self.batch_size = batch_size
        self.batch_timeout = batch_timeout
        self.agent_interval = agent_interval

        self.event_batch = []
        self.batch_lock = threading.Lock()
        self.batch_last_sent = time.time()

        self.retry_queue = queue.Queue(maxsize=batch_retry_queue_size)
        self.consecutive_failures = 0
        self.failure_lock = threading.Lock()
        self.current_backoff = initial_retry_delay
        self.max_batch_retries = max_batch_retries
        self.initial_retry_delay = initial_retry_delay
        self.max_retry_delay = max_retry_delay
        self.max_consecutive_failures = max_consecutive_failures
        self.backoff_multiplier = backoff_multiplier

        self.retry_thread: Optional[threading.Thread] = None
        self.retry_thread_running = True

        self.state = {}
        self.file_position = 0
        self.processed_hashes = set()
        self.stats = {
            "logs_processed": 0,
            "logs_duplicated": 0,
            "logs_filtered": 0,
            "events_sent": 0,
            "unique_events": 0,
        }
        self._load_state(state_dir)

    def _get_state_path(self, state_dir: Optional[str]) -> Path:
        """Obtiene la ruta del archivo de estado."""
        if state_dir:
            base = Path(state_dir)
        else:
            base = Path(__file__).parent
        base.mkdir(parents=True, exist_ok=True)
        return base / f"{self.agent_id}_state.json"

    def _load_state(self, state_dir: Optional[str] = None):
        """Carga el estado desde disco."""
        state_path = self._get_state_path(state_dir)
        if state_path.exists():
            try:
                with open(state_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.state = data.get("state", {})
                    self.file_position = data.get("file_position", 0)
                    self.processed_hashes = set(data.get("processed_hashes", []))
                    self.stats = data.get("stats", self.stats)
                logger.info(
                    "[%s] Estado cargado desde %s", self.agent_id, state_path
                )
            except (json.JSONDecodeError, IOError) as err:
                logger.warning(
                    "[%s] Error cargando estado: %s", self.agent_id, err
                )

    def _save_state(self):
        """Guarda el estado en disco."""
        state_path = self._get_state_path(None)
        try:
            data = {
                "state": self.state,
                "file_position": self.file_position,
                "processed_hashes": list(self.processed_hashes)[:10000],
                "stats": self.stats,
            }
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except IOError as err:
            logger.error("[%s] Error guardando estado: %s", self.agent_id, err)

    def get_system_info(self) -> dict:
        """Obtiene informacion del sistema operativo."""
        return {
            "os": platform.system(),
            "os_version": platform.version(),
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
        }

    def _compute_hash(self, text: str) -> str:
        """Computa hash simple para deduplicacion."""
        return str(hash(text) % 10**12)

    def is_processed(self, line: str) -> bool:
        """Verifica si una linea ya fue procesada."""
        h = self._compute_hash(line)
        return h in self.processed_hashes

    def mark_processed(self, line: str):
        """Marca una linea como procesada."""
        h = self._compute_hash(line)
        self.processed_hashes.add(h)
        if len(self.processed_hashes) > 20000:
            self.processed_hashes = set(list(self.processed_hashes)[-10000:])

    def update_stats(self, key: str, value: int = 1):
        """Actualiza estadisticas."""
        self.stats[key] = self.stats.get(key, 0) + value

    def get_stats(self) -> dict:
        """Retorna estadisticas actuales."""
        return self.stats.copy()

    def set_file_position(self, pos: int):
        """Establece la posicion en el archivo."""
        self.file_position = pos

    def get_file_position(self) -> int:
        """Obtiene la posicion actual en el archivo."""
        return self.file_position

    def _send_to_server(self, data: dict, is_retry: bool = False) -> tuple:
        """Envia datos al servidor con firmas de seguridad."""
        nonce = generate_nonce()
        timestamp = int(time.time())
        
        body = json.dumps(data).encode()
        
        headers = {
            "X-API-Key": self.api_key,
            "Content-Type": "application/json",
            "X-Request-ID": nonce,
            "X-Request-Timestamp": str(timestamp),
            "User-Agent": f"SOC-Agent/{self.agent_id}",
        }
        
        if self.api_secret:
            signature = generate_signature(
                "POST", "/log", nonce, timestamp, body, self.api_secret
            )
            headers["X-Request-Signature"] = signature
        
        try:
            response = requests.post(
                self.server_url,
                json=data,
                headers=headers,
                timeout=self.request_timeout,
                verify=self.verify_ssl,
            )

            if response.status_code == 429:
                logger.warning("[%s] Rate limited", self.agent_id)
                return False, "rate_limited"

            if response.status_code == 503:
                logger.warning("[%s] Server overloaded", self.agent_id)
                return False, "overloaded"

            response.raise_for_status()
            
            if self.api_secret:
                resp_nonce = response.headers.get("X-Response-Nonce")
                resp_timestamp = response.headers.get("X-Response-Timestamp")
                resp_signature = response.headers.get("X-Response-Signature")
                
                if resp_timestamp:
                    time_diff = abs(time.time() - int(resp_timestamp))
                    if time_diff > 300:
                        logger.warning("[%s] Response timestamp too old", self.agent_id)
                        return False, "invalid_response"
                
                if not validate_response_signature(
                    resp_nonce, resp_timestamp, resp_signature,
                    "POST", "/log", body, self.api_secret
                ):
                    logger.warning("[%s] Invalid response signature", self.agent_id)
                    return False, "invalid_signature"

            with self.failure_lock:
                self.consecutive_failures = 0
                self.current_backoff = self.initial_retry_delay

            return True, None

        except requests.exceptions.Timeout:
            logger.error("[%s] Request timeout", self.agent_id)
            return False, "timeout"
        except requests.exceptions.ConnectionError:
            logger.error("[%s] Server not reachable", self.agent_id)
            return False, "connection_error"
        except requests.exceptions.HTTPError as err:
            if err.response and err.response.status_code >= 500:
                logger.error("[%s] Server error: %s", self.agent_id, err)
                return False, "server_error"
            logger.error("[%s] HTTP error: %s", self.agent_id, err)
            return False, "http_error"
        except Exception as err:  # pylint: disable=broad-except
            logger.error("[%s] Error: %s", self.agent_id, err)
            return False, "unknown"

    def _send_batch(self, batch: list) -> tuple:
        """Envia un lote de eventos con firmas de seguridad."""
        if not batch:
            return True, None

        logger.info("[%s] Sending batch of %d events", self.agent_id, len(batch))

        payload = {"events": [{"event": event} for event in batch]}
        
        nonce = generate_nonce()
        timestamp = int(time.time())
        body = json.dumps(payload).encode()
        
        headers = {
            "X-API-Key": self.api_key,
            "Content-Type": "application/json",
            "X-Request-ID": nonce,
            "X-Request-Timestamp": str(timestamp),
            "User-Agent": f"SOC-Agent/{self.agent_id}",
        }
        
        if self.api_secret:
            signature = generate_signature(
                "POST", "/log/batch", nonce, timestamp, body, self.api_secret
            )
            headers["X-Request-Signature"] = signature

        try:
            response = requests.post(
                self.batch_url,
                json=payload,
                headers=headers,
                timeout=self.request_timeout,
                verify=self.verify_ssl,
            )

            if response.status_code == 429:
                logger.warning("[%s] Rate limited", self.agent_id)
                for event in batch:
                    self._queue_retry(event)
                return False, "rate_limited"

            if response.status_code == 503:
                logger.warning("[%s] Server overloaded", self.agent_id)
                for event in batch:
                    self._queue_retry(event)
                return False, "overloaded"

            response.raise_for_status()

            for event in batch:
                self.update_stats("events_sent")
                logger.info(
                    "[%s] Sent: %s from %s",
                    self.agent_id,
                    event.get("attack_type"),
                    event.get("src_ip"),
                )

            return True, None

        except requests.exceptions.Timeout:
            logger.error("[%s] Batch timeout", self.agent_id)
            for event in batch:
                self._queue_retry(event)
            return False, "timeout"
        except requests.exceptions.ConnectionError:
            logger.error("[%s] Server not reachable", self.agent_id)
            for event in batch:
                self._queue_retry(event)
            return False, "connection_error"
        except requests.exceptions.HTTPError as err:
            if err.response and err.response.status_code >= 500:
                logger.error("[%s] Server error: %s", self.agent_id, err)
                for event in batch:
                    self._queue_retry(event)
                return False, "server_error"
            logger.error("[%s] HTTP error: %s", self.agent_id, err)
            return False, "http_error"
        except Exception as err:  # pylint: disable=broad-except
            logger.error("[%s] Error: %s", self.agent_id, err)
            return False, "unknown"

    def _queue_retry(self, data: dict):
        """Agrega un evento a la cola de reintentos."""
        try:
            self.retry_queue.put_nowait(
                {"data": data, "retry_count": 0, "last_attempt": time.time()}
            )
        except queue.Full:
            logger.warning("[%s] Retry queue full, dropping event", self.agent_id)

    def send_event(self, data: dict):
        """Envia un evento individual al servidor."""
        self.update_stats("events_sent")
        logger.info(
            "[%s] Sent: %s from %s",
            self.agent_id,
            data.get("attack_type"),
            data.get("src_ip"),
        )

        success, error_type = self._send_to_server(data)

        if not success and error_type in (
            "rate_limited",
            "overloaded",
            "timeout",
            "connection_error",
        ):
            self._queue_retry(data)

    def send_event_async(self, data: dict):
        """Envia un evento de manera asincrona (batching)."""
        with self.batch_lock:
            self.event_batch.append(data)

            should_send = (
                len(self.event_batch) >= self.batch_size
                or (time.time() - self.batch_last_sent) >= self.batch_timeout
            )

            if should_send and self.event_batch:
                self._send_batch(self.event_batch.copy())
                self.event_batch = []
                self.batch_last_sent = time.time()

    def flush_batch(self):
        """Fuerza el envio del batch actual."""
        with self.batch_lock:
            if self.event_batch:
                self._send_batch(self.event_batch.copy())
                self.event_batch = []
                self.batch_last_sent = time.time()

    def retry_worker(self):
        """Hilo worker para procesar eventos en la cola de reintentos."""
        while self.retry_thread_running:
            try:
                item = self.retry_queue.get(timeout=1)

                if item["retry_count"] >= self.max_batch_retries:
                    logger.warning(
                        "[%s] Max retries reached, dropping event", self.agent_id
                    )
                    self.retry_queue.task_done()
                    continue

                time_since_last = time.time() - item["last_attempt"]
                if time_since_last < self.current_backoff:
                    remaining = self.current_backoff - time_since_last
                    time.sleep(min(remaining, 5))

                if not self.retry_thread_running:
                    self.retry_queue.task_done()
                    continue

                success, _ = self._send_to_server(item["data"], is_retry=True)

                if success:
                    self.update_stats("events_sent")
                    logger.info(
                        "[%s] Retry successful: %s",
                        self.agent_id,
                        item["data"].get("attack_type"),
                    )
                    self.retry_queue.task_done()
                else:
                    item["retry_count"] += 1
                    item["last_attempt"] = time.time()

                    with self.failure_lock:
                        self.consecutive_failures += 1
                        if self.consecutive_failures > 1:
                            self.current_backoff = min(
                                self.current_backoff * self.backoff_multiplier,
                                self.max_retry_delay,
                            )

                    try:
                        self.retry_queue.put_nowait(item)
                    except queue.Full:
                        logger.warning(
                            "[%s] Retry queue full, dropping event", self.agent_id
                        )

                    self.retry_queue.task_done()

            except queue.Empty:
                continue
            except Exception as err:  # pylint: disable=broad-except
                logger.error("[%s] Retry worker error: %s", self.agent_id, err)

            time.sleep(0.1)

    def start_retry_worker(self):
        """Inicia el hilo de reintentos."""
        if self.retry_thread is None or not self.retry_thread.is_alive():
            self.retry_thread_running = True
            self.retry_thread = threading.Thread(
                target=self.retry_worker, daemon=True
            )
            self.retry_thread.start()
            logger.info("[%s] Retry worker started", self.agent_id)

    def stop_retry_worker(self):
        """Detiene el hilo de reintentos."""
        self.retry_thread_running = False
        if self.retry_thread:
            self.retry_thread.join(timeout=5)

    def build_event(
        self,
        attack_type: str,
        src_ip: str,
        risk: int = 0,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        user: Optional[str] = None,
        match_data: Any = None,
        duration: int = 0,
        attempts_count: int = 0,
        extra_data: Optional[dict] = None,
        log_timestamp: Optional[datetime] = None,
    ) -> dict:
        """Construye el payload del evento."""
        event_time = log_timestamp if log_timestamp else datetime.now()

        extra = extra_data.copy() if extra_data else {}
        extra["system_info"] = self.get_system_info()
        if user:
            extra["user"] = user
        if attempts_count > 0:
            extra["attempts_count"] = attempts_count
        if duration > 0:
            extra["attack_duration_seconds"] = duration

        return {
            "agent_id": self.agent_id,
            "target_host": getattr(self, "target_host", "unknown"),
            "target_service": getattr(self, "target_service", "web"),
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "risk": risk,
            "severity": self._determine_severity(risk),
            "attack_type": attack_type,
            "source": getattr(self, "source", "web"),
            "event_time": event_time.isoformat(),
            "report_time": datetime.now().isoformat(),
            "duration": duration,
            "raw_log": match_data.group(0) if match_data else None,
            "extra_data": json.dumps(extra),
        }

    @staticmethod
    def _determine_severity(risk: int) -> str:
        """Determina la severidad basada en el riesgo."""
        if risk >= 50:
            return "CRITICAL"
        if risk >= 30:
            return "HIGH"
        if risk >= 15:
            return "MEDIUM"
        return "LOW"

    def read_log_lines(self) -> list:
        """Lee las lineas nuevas del archivo de log."""
        if not os.path.exists(self.log_file):
            logger.warning(
                "[%s] Archivo no encontrado: %s", self.agent_id, self.log_file
            )
            return []

        try:
            with open(self.log_file, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(self.get_file_position())
                lines = f.readlines()
                self.set_file_position(f.tell())
            return lines
        except IOError as err:
            logger.error("[%s] Error leyendo archivo: %s", self.agent_id, err)
            return []

    def monitor(self):
        """Funcion de monitoreo a ser implementada por subclases."""
        raise NotImplementedError("Subclases deben implementar monitor()")

    def run(self):
        """Punto de entrada principal."""
        logger.info("=" * 50)
        logger.info("%s - Iniciado", self.__class__.__name__)
        logger.info("  Agent ID: %s", self.agent_id)
        logger.info("  Log File: %s", self.log_file)
        logger.info("  Server: %s", self.server_url)
        logger.info("  Batch Mode: %s", self.use_batch_mode)
        if self.use_batch_mode:
            logger.info(
                "  Batch Size: %d, Timeout: %ds",
                self.batch_size,
                self.batch_timeout,
            )
        logger.info("=" * 50)

        logger.info("[%s] Estado actual: %s", self.agent_id, self.get_stats())

        self.start_retry_worker()

        cycle = 0
        try:
            while True:
                self.monitor()

                if self.use_batch_mode and cycle % 5 == 0:
                    self.flush_batch()

                cycle += 1

                if cycle % 10 == 0:
                    stats = self.get_stats()
                    retry_queue_size = self.retry_queue.qsize()
                    logger.info(
                        "[%s] Stats: processed=%d, duplicated=%d, "
                        "filtered=%d, events_sent=%d, unique_events=%d, "
                        "retry_queue=%d",
                        self.agent_id,
                        stats["logs_processed"],
                        stats["logs_duplicated"],
                        stats["logs_filtered"],
                        stats["events_sent"],
                        stats["unique_events"],
                        retry_queue_size,
                    )

                time.sleep(self.agent_interval)
        except KeyboardInterrupt:
            logger.info("[%s] Shutting down...", self.agent_id)
        finally:
            self.flush_batch()
            self.stop_retry_worker()
            self._save_state()
            logger.info("[%s] Agent stopped", self.agent_id)
