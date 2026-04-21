"""
Modulo de persistencia del estado del Agente SOC.

Maneja la persistencia de:
- Posicion del archivo de log
- Hashes de logs ya procesados ( deduplicacion )
- Estado de ataques en curso
- Intentos por IP (para deteccion de fuerza bruta)
- Cooldowns de envio de alertas
- Estadisticas de procesamiento
- Historial de eventos por IP (correlacion)

Uso:
    from persistence import AgentState
    state = AgentState("agent_001")
    state.save()
"""

import hashlib
import json
import logging
import time
from datetime import datetime, timedelta
from pathlib import Path

try:
    from config import STATE_DIR
except ImportError:
    STATE_DIR = None

logger = logging.getLogger(__name__)

DEFAULT_STATE_FILE = "agent_state.json"
MAX_HASHES = 10000
HASH_RETENTION_HOURS = 24
ATTEMPTS_RETENTION_MINUTES = 30
COOLDOWN_RETENTION_HOURS = 1


class AgentState:
    """Gestiona el estado persistente del agente."""

    def __init__(self, agent_id, state_dir=None):
        self.agent_id = agent_id
        if state_dir:
            self.state_dir = Path(state_dir)
        elif STATE_DIR:
            self.state_dir = Path(STATE_DIR)
        else:
            self.state_dir = Path(__file__).parent
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.state_file = self.state_dir / f"{agent_id}_state.json"

        self.file_position = 0
        self.processed_hashes = {}
        self.attack_states = {}
        self.attempts = {}
        self.cooldowns = {}
        self.ip_event_history = {}
        self.stats = {
            "logs_processed": 0,
            "logs_duplicated": 0,
            "logs_filtered": 0,
            "events_sent": 0,
            "unique_events": 0,
            "last_reset": datetime.now().isoformat()
        }

        self.load()

    def _hash_log(self, line):
        """Genera hash unico para una linea de log."""
        return hashlib.sha256(
            line.encode('utf-8', errors='ignore')
        ).hexdigest()[:16]

    def is_processed(self, line):
        """Verifica si una linea ya fue procesada."""
        h = self._hash_log(line)
        if h in self.processed_hashes:
            entry = self.processed_hashes[h]
            if isinstance(entry, dict):
                timestamp = datetime.fromisoformat(
                    entry.get("timestamp", "2000-01-01")
                )
                age_hours = (datetime.now() - timestamp).total_seconds() / 3600
                if age_hours > HASH_RETENTION_HOURS:
                    del self.processed_hashes[h]
                    return False
            return True
        return False

    def mark_processed(self, line):
        """Marca una linea como procesada."""
        h = self._hash_log(line)
        self.processed_hashes[h] = {
            "timestamp": datetime.now().isoformat(),
            "count": self.processed_hashes.get(h, {}).get("count", 0) + 1
        }

        if len(self.processed_hashes) > MAX_HASHES:
            self._cleanup_old_hashes()

    def _cleanup_old_hashes(self):
        """Elimina hashes antiguos para mantener limite de memoria."""
        sorted_hashes = sorted(
            self.processed_hashes.items(),
            key=lambda x: x[1].get("timestamp", "2000-01-01")
            if isinstance(x[1], dict) else "2000-01-01"
        )
        keep_count = MAX_HASHES // 2
        self.processed_hashes = dict(sorted_hashes[-keep_count:])

    def get_file_position(self):
        """Obtiene la posicion actual del archivo."""
        return self.file_position

    def set_file_position(self, pos):
        """Establece la posicion actual del archivo."""
        self.file_position = pos

    def set_attack_state(self, ip, state_data):
        """Establece el estado de ataque para una IP."""
        self.attack_states[ip] = state_data

    def get_attack_state(self, ip):
        """Obtiene el estado de ataque para una IP."""
        return self.attack_states.get(ip)

    def remove_attack_state(self, ip):
        """Elimina el estado de ataque para una IP."""
        if ip in self.attack_states:
            del self.attack_states[ip]

    def get_all_attack_states(self):
        """Obtiene lista de IPs con ataques activos."""
        return list(self.attack_states.keys())

    def update_attempts(self, ip, event_time_str, attempt_data=None):
        """Actualiza intentos para una IP."""
        if ip not in self.attempts:
            self.attempts[ip] = []

        self.attempts[ip].append({
            "time": event_time_str,
            "data": attempt_data or {}
        })

        self.attempts[ip] = self._filter_old_attempts(ip)
        return self.attempts[ip]

    def get_attempts(self, ip):
        """Obtiene intentos validos para una IP."""
        self.attempts[ip] = self._filter_old_attempts(ip)
        return self.attempts[ip]

    def _filter_old_attempts(self, ip):
        """Filtra intentos antiguos."""
        if ip not in self.attempts:
            return []

        cutoff = datetime.now() - timedelta(minutes=ATTEMPTS_RETENTION_MINUTES)
        filtered = []

        for attempt in self.attempts[ip]:
            try:
                event_time = datetime.fromisoformat(attempt["time"])
                if event_time > cutoff:
                    filtered.append(attempt)
            except (ValueError, KeyError):
                continue

        return filtered

    def clear_attempts(self, ip):
        """Limpia intentos para una IP."""
        if ip in self.attempts:
            self.attempts[ip] = []

    def check_cooldown(self, key):
        """Verifica si una clave esta en cooldown."""
        self._cleanup_cooldowns()
        return self.cooldowns.get(key)

    def set_cooldown(self, key, value=None):
        """Establece un cooldown."""
        if value is None:
            value = time.time()
        self.cooldowns[key] = value

    def _cleanup_cooldowns(self):
        """Limpia cooldowns antiguos."""
        cutoff = datetime.now() - timedelta(hours=COOLDOWN_RETENTION_HOURS)
        cutoff_ts = cutoff.timestamp()

        self.cooldowns = {
            k: v for k, v in self.cooldowns.items()
            if v > cutoff_ts
        }

    def should_send(self, ip, event_type, _severity, cooldown_seconds):
        """Determina si debe enviarse un evento basado en cooldown."""
        key = f"{ip}:{event_type}"
        now = time.time()

        last_time = self.check_cooldown(key)
        if last_time and now - last_time < cooldown_seconds:
            return False

        self.set_cooldown(key, now)
        return True

    def check_retry_cooldown(self, key):
        """Verifica si un evento ya esta en retry cooldown."""
        retry_cooldown_key = f"retry_{key}"
        return self.check_cooldown(retry_cooldown_key)

    def set_retry_cooldown(self, key, seconds=None):
        """Establece cooldown para evitar reintentos duplicados."""
        retry_cooldown_key = f"retry_{key}"
        cooldown_time = seconds or 300
        self.set_cooldown(retry_cooldown_key, time.time() + cooldown_time)

    def update_stats(self, stat_name, value=1):
        """Actualiza estadisticas de procesamiento."""
        if stat_name in self.stats:
            self.stats[stat_name] += value

    def record_ip_event(self, src_ip, event_type, event_time=None):
        """
        Registra un evento en el historial de la IP para correlacion.

        Mantiene los ultimos 50 eventos por IP con ventana de 24 horas.
        """
        if src_ip is None:
            return

        if src_ip not in self.ip_event_history:
            self.ip_event_history[src_ip] = []

        event_record = {
            "type": event_type,
            "time": event_time or datetime.now().isoformat()
        }

        self.ip_event_history[src_ip].append(event_record)
        self.ip_event_history[src_ip] = self._cleanup_ip_history(src_ip)

        if len(self.ip_event_history) > 1000:
            self._cleanup_old_ips()

    def _cleanup_ip_history(self, src_ip):
        """Limpia eventos antiguos de una IP (ventana de 24 horas)."""
        if src_ip not in self.ip_event_history:
            return []

        cutoff = datetime.now() - timedelta(hours=24)
        cleaned = []

        for event in self.ip_event_history[src_ip]:
            try:
                evt_time = datetime.fromisoformat(event["time"])
                if evt_time > cutoff:
                    cleaned.append(event)
            except (ValueError, KeyError):
                continue

        return cleaned[-50:]

    def _cleanup_old_ips(self):
        """Limpia IPs sin actividad reciente."""
        cutoff = datetime.now() - timedelta(hours=24)

        for ip in list(self.ip_event_history.keys()):
            events = self.ip_event_history[ip]
            has_recent = False
            for event in events:
                try:
                    evt_time = datetime.fromisoformat(event["time"])
                    if evt_time > cutoff:
                        has_recent = True
                        break
                except (ValueError, KeyError):
                    continue
            if not has_recent:
                del self.ip_event_history[ip]

    def get_ip_event_count(self, src_ip, event_type=None, hours=24):
        """
        Obtiene el conteo de eventos de una IP.

        Args:
            src_ip: IP de origen
            event_type: Tipo de evento especifico (None = todos)
            hours: Ventana de tiempo en horas

        Returns:
            Numero de eventos en la ventana de tiempo
        """
        if src_ip not in self.ip_event_history:
            return 0

        cutoff = datetime.now() - timedelta(hours=hours)
        count = 0

        for event in self.ip_event_history[src_ip]:
            try:
                evt_time = datetime.fromisoformat(event["time"])
                if evt_time > cutoff:
                    if event_type is None or event["type"] == event_type:
                        count += 1
            except (ValueError, KeyError):
                continue

        return count

    def has_recent_brute_force(self, src_ip, hours=24):
        """Verifica si la IP tuvo brute force reciente."""
        return self.get_ip_event_count(src_ip, "brute_force_start", hours) > 0

    def has_failed_attempts(self, src_ip, hours=24):
        """Verifica si la IP tuvo intentos fallidos recientes."""
        return self.get_ip_event_count(src_ip, "ssh_brute_force", hours) > 0

    def correlate_ssh_login(self, src_ip, _user=None):
        """
        Evalua el riesgo de un login SSH basandose en correlacion.

        Segun NIST SP 800-53 y MITRE ATT&CK T1078:
        - Login sin precedentes: Riesgo INFO (20)
        - Login con brute force previo: Riesgo CRITICAL (70-100)
        - Login con intentos fallidos: Riesgo MEDIUM-HIGH

        Args:
            src_ip: IP de origen del login
            _user: Usuario (no usado, reservado para futuras correlaciones)

        Returns:
            tuple: (risk_score, correlation_context)
        """
        context = {
            "has_brute_force": False,
            "has_failed_attempts": False,
            "failed_attempt_count": 0,
            "brute_force_count": 0,
            "risk_level": "UNKNOWN"
        }

        failed_count = self.get_ip_event_count(src_ip, "ssh_brute_force", 24)
        brute_force_count = self.get_ip_event_count(
            src_ip, "brute_force_start", 24
        )

        context["has_failed_attempts"] = failed_count > 0
        context["failed_attempt_count"] = failed_count
        context["brute_force_count"] = brute_force_count
        context["has_brute_force"] = brute_force_count > 0

        if brute_force_count > 0:
            context["risk_level"] = "CRITICAL"
            risk = min(100 + (brute_force_count * 10), 200)
        elif failed_count >= 3:
            context["risk_level"] = "HIGH"
            risk = 50 + min(failed_count * 5, 30)
        elif failed_count > 0:
            context["risk_level"] = "MEDIUM"
            risk = 30 + min(failed_count * 5, 20)
        else:
            context["risk_level"] = "INFO"
            risk = 20

        return risk, context

    def get_stats(self):
        """Obtiene estadisticas actuales."""
        return {
            **self.stats,
            "active_attacks": len(self.attack_states),
            "hashes_tracked": len(self.processed_hashes),
            "ips_tracked": len(self.attempts)
        }

    def reset_stats(self):
        """Resetea todas las estadisticas."""
        self.stats = {
            "logs_processed": 0,
            "logs_duplicated": 0,
            "logs_filtered": 0,
            "events_sent": 0,
            "unique_events": 0,
            "last_reset": datetime.now().isoformat()
        }
        self.save()

    def save(self):
        """Guarda el estado en disco."""
        try:
            data = {
                "agent_id": self.agent_id,
                "file_position": self.file_position,
                "processed_hashes": self.processed_hashes,
                "attack_states": self.attack_states,
                "attempts": self.attempts,
                "cooldowns": self.cooldowns,
                "ip_event_history": self.ip_event_history,
                "stats": self.stats,
                "saved_at": datetime.now().isoformat()
            }
            with open(self.state_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str)
            logger.debug(
                "[%s] Estado guardado: %s",
                self.agent_id, self.state_file
            )
        except OSError as e:
            logger.error(
                "[%s] Error guardando estado: %s",
                self.agent_id, str(e)
            )
        except TypeError as e:
            logger.error(
                "[%s] Error serializando estado: %s",
                self.agent_id, str(e)
            )

    def load(self):
        """Carga el estado desde disco."""
        if not self.state_file.exists():
            return

        try:
            with open(self.state_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            self.file_position = data.get("file_position", 0)
            self.processed_hashes = data.get("processed_hashes", {})
            self.attack_states = data.get("attack_states", {})
            self.attempts = data.get("attempts", {})
            self.cooldowns = data.get("cooldowns", {})
            self.ip_event_history = data.get("ip_event_history", {})
            self.stats = data.get("stats", self.stats)

            logger.info(
                "[%s] Estado cargado: %d hashes, %d ataques activos, "
                "%d IPs rastreadas",
                self.agent_id,
                len(self.processed_hashes),
                len(self.attack_states),
                len(self.attempts)
            )
        except OSError as e:
            logger.error(
                "[%s] Error cargando estado: %s",
                self.agent_id, str(e)
            )
        except json.JSONDecodeError as e:
            logger.error(
                "[%s] Error decodificando estado: %s",
                self.agent_id, str(e)
            )
