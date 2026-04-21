"""
Base de datos SQLite para el SOC Platform.

Este modulo maneja toda la interaccion con la base de datos:
- Creacion de tablas
- Insercion de logs de seguridad
- Consultas para estadisticas
- Indices para optimizar busquedas

La base de datos usa SQLite por su simplicidad y no requiere
instalacion de servidor adicional.
"""

import json
import sqlite3
from contextlib import contextmanager


import os
from pathlib import Path

_SERVER_DIR = Path(__file__).resolve().parent
DB_NAME = str(_SERVER_DIR / "database.db")


@contextmanager
def get_connection():
    """
    Context manager para conexiones a la base de datos.

    Asegura que la conexion se cierre correctamente incluso si
    ocurre un error durante la ejecucion.

    Uso:
        with get_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM logs")
            results = c.fetchall()
    """
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    """Crea las tablas necesarias si no existen."""
    with get_connection() as conn:
        c = conn.cursor()

        c.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_time TEXT,
                report_time TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                src_ip TEXT,
                src_port INTEGER,
                protocol TEXT,
                agent_id TEXT NOT NULL,
                target_host TEXT,
                target_port INTEGER,
                target_service TEXT,
                source TEXT,
                attack_type TEXT,
                risk INTEGER NOT NULL,
                severity TEXT,
                raw_log TEXT,
                duration INTEGER,
                country TEXT,
                extra_data TEXT
            )
        """)

        c.execute("CREATE INDEX IF NOT EXISTS idx_logs_src_ip ON logs(src_ip)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_logs_risk ON logs(risk)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_logs_agent ON logs(agent_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_logs_source ON logs(source)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_logs_attack_type ON logs(attack_type)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_logs_target_host ON logs(target_host)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_logs_severity ON logs(severity)")

        c.execute("""
            CREATE TABLE IF NOT EXISTS agents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT UNIQUE NOT NULL,
                hostname TEXT,
                ip_address TEXT,
                os_info TEXT,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'active',
                metadata TEXT
            )
        """)

        c.execute("CREATE INDEX IF NOT EXISTS idx_agents_agent_id ON agents(agent_id)")

        c.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                src_ip TEXT NOT NULL,
                agent_id TEXT,
                risk INTEGER NOT NULL,
                attack_type TEXT,
                last_sent DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        c.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts(src_ip)")
        c.execute(
            "CREATE INDEX IF NOT EXISTS idx_alerts_composite "
            "ON alerts(src_ip, agent_id, attack_type)"
        )

        c.execute("""
            CREATE TABLE IF NOT EXISTS threat_intel (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                attack_types TEXT,
                agent_ids TEXT,
                agent_count INTEGER DEFAULT 1,
                max_risk INTEGER DEFAULT 0,
                avg_risk REAL DEFAULT 0,
                is_compromised BOOLEAN DEFAULT 0,
                is_coordinated BOOLEAN DEFAULT 0,
                recommendations TEXT,
                event_count INTEGER DEFAULT 1,
                details TEXT,
                UNIQUE(ip)
            )
        """)

        c.execute("CREATE INDEX IF NOT EXISTS idx_threat_ip ON threat_intel(ip)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_threat_compromised ON threat_intel(is_compromised)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_threat_coordinated ON threat_intel(is_coordinated)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_threat_risk ON threat_intel(max_risk)")

        conn.commit()


def insert_log(
    src_ip, risk, agent_id, attack_type,
    event_time=None, report_time=None,
    src_port=None, protocol=None, target_host=None, target_port=None,
    target_service=None, source=None, severity=None,
    raw_log=None, duration=None, extra_data=None
):
    """
    Inserta un nuevo evento de log en la base de datos.

    Args:
        src_ip: IP origen del ataque.
        risk: Nivel de riesgo (0-100+).
        agent_id: ID del agente que reporto.
        attack_type: Tipo de ataque detectado.
        event_time: Tiempo del evento original (string).
        report_time: Tiempo del reporte (string).
        src_port: Puerto origen.
        protocol: Protocolo (TCP, UDP, ICMP, HTTP, etc.).
        target_host: Host que esta siendo attackado.
        target_port: Puerto objetivo.
        target_service: Servicio afectado (ssh, http, etc.).
        source: Fuente del log (auth.log, suricata.log, etc.).
        severity: Severidad (LOW, MEDIUM, HIGH, CRITICAL).
        raw_log: Log original para debug.
        duration: Duracion en segundos.
        extra_data: JSON con datos adicionales.
    """
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("""
            INSERT INTO logs (
                event_time, report_time, src_ip, src_port, protocol,
                agent_id, target_host, target_port, target_service, source,
                attack_type, risk, severity, raw_log, duration, country, extra_data
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event_time, report_time, src_ip, src_port, protocol,
            agent_id, target_host, target_port, target_service, source,
            attack_type, risk, severity, raw_log, duration, None, extra_data
        ))
        conn.commit()


def log_exists(src_ip, risk, attack_type, agent_id=None):
    """
    Verifica si ya existe un log similar (para evitar duplicados).

    Args:
        src_ip: IP origen.
        risk: Nivel de riesgo.
        attack_type: Tipo de ataque.
        agent_id: ID del agente (opcional).

    Returns:
        bool: True si ya existe, False si no.
    """
    with get_connection() as conn:
        c = conn.cursor()
        if agent_id:
            c.execute("""
                SELECT 1 FROM logs
                WHERE src_ip = ? AND risk = ? AND attack_type = ? AND agent_id = ?
                LIMIT 1
            """, (src_ip, risk, attack_type, agent_id))
        else:
            c.execute("""
                SELECT 1 FROM logs
                WHERE src_ip = ? AND risk = ? AND attack_type = ?
                LIMIT 1
            """, (src_ip, risk, attack_type))
        return c.fetchone() is not None


def log_exists_compound(src_ip, risk, attack_type, agent_id, event_timestamp,
                        window_minutes=60, max_age_hours=24):
    """
    Verifica duplicados usando clave compuesta y ventanas de tiempo.

    Implementa deduplicacion robusta considerando:
    - IP origen
    - Tipo de ataque
    - Nivel de riesgo
    - Agente que reporta
    - Timestamp del evento (event_time, no report_time)
    - Ventana de tiempo configurable

    Args:
        src_ip: IP origen.
        risk: Nivel de riesgo.
        attack_type: Tipo de ataque.
        agent_id: ID del agente.
        event_timestamp: Timestamp del evento (ISO format o datetime).
        window_minutes: Ventana de deduplicacion en minutos.
        max_age_hours: Maximo tiempo en horas para aceptar eventos.

    Returns:
        tuple: (is_duplicate, is_too_old, existing_log_id)
            - is_duplicate: True si el evento ya existe en la ventana
            - is_too_old: True si el evento es muy antiguo
            - existing_log_id: ID del log existente si hay duplicado
    """
    from datetime import datetime, timedelta

    with get_connection() as conn:
        c = conn.cursor()

        try:
            if isinstance(event_timestamp, str):
                ts_str = event_timestamp.replace('Z', '+00:00').replace(' ', 'T')
                event_dt = datetime.fromisoformat(ts_str)
            else:
                event_dt = event_timestamp
        except:
            try:
                event_dt = datetime.strptime(event_timestamp, "%Y-%m-%d %H:%M:%S.%f")
            except:
                event_dt = datetime.now()

        now = datetime.now()
        try:
            event_dt_naive = event_dt.replace(tzinfo=None) if event_dt.tzinfo else event_dt
            age_hours = (now - event_dt_naive).total_seconds() / 3600
        except:
            age_hours = 0

        if age_hours > max_age_hours:
            return (False, True, None)

        event_dt_naive = event_dt.replace(tzinfo=None) if event_dt.tzinfo else event_dt
        window_start = event_dt_naive - timedelta(minutes=window_minutes)
        window_end = event_dt_naive + timedelta(minutes=window_minutes)

        c.execute("""
            SELECT id, event_time FROM logs
            WHERE src_ip = ?
              AND risk = ?
              AND attack_type = ?
              AND agent_id = ?
              AND event_time >= ?
              AND event_time <= ?
            LIMIT 1
        """, (
            src_ip, risk, attack_type, agent_id,
            window_start.isoformat(),
            window_end.isoformat()
        ))

        existing = c.fetchone()
        if existing:
            return (True, False, existing["id"])

        return (False, False, None)


def register_agent(agent_id, hostname=None, ip_address=None,
                  os_info=None, metadata=None):
    """
    Registra o actualiza un agente en la base de datos.

    Args:
        agent_id: ID unico del agente.
        hostname: Nombre del host.
        ip_address: IP del agente.
        os_info: Informacion del sistema operativo.
        metadata: JSON con informacion adicional.
    """
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("""
            INSERT INTO agents (agent_id, hostname, ip_address, os_info, metadata)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(agent_id) DO UPDATE SET
                hostname = COALESCE(?, hostname),
                ip_address = COALESCE(?, ip_address),
                os_info = COALESCE(?, os_info),
                metadata = COALESCE(?, metadata),
                last_seen = CURRENT_TIMESTAMP
        """, (
            agent_id, hostname, ip_address, os_info,
            json.dumps(metadata) if metadata else None,
            hostname, ip_address, os_info,
            json.dumps(metadata) if metadata else None
        ))
        conn.commit()


def update_agent_status(agent_id, status='active'):
    """Actualiza el estado de un agente."""
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("""
            UPDATE agents
            SET status = ?, last_seen = CURRENT_TIMESTAMP
            WHERE agent_id = ?
        """, (status, agent_id))
        conn.commit()


def get_all_agents():
    """Obtiene lista de todos los agentes registrados."""
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM agents ORDER BY last_seen DESC")
        return c.fetchall()


def get_agent_by_id(agent_id):
    """Obtiene un agente por su ID."""
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,))
        return c.fetchone()


def alert_exists(src_ip, risk, agent_id=None, attack_type=None):
    """
    Verifica si ya se envio una alerta similar recientemente.

    Args:
        src_ip: IP origen.
        risk: Nivel de riesgo.
        agent_id: ID del agente (opcional).
        attack_type: Tipo de ataque (opcional).

    Returns:
        bool: True si ya existe, False si no.
    """
    with get_connection() as conn:
        c = conn.cursor()
        if agent_id and attack_type:
            c.execute("""
                SELECT 1 FROM alerts
                WHERE src_ip = ? AND risk = ? AND agent_id = ? AND attack_type = ?
                AND last_sent > datetime('now', '-5 minutes')
                LIMIT 1
            """, (src_ip, risk, agent_id, attack_type))
        elif agent_id:
            c.execute("""
                SELECT 1 FROM alerts
                WHERE src_ip = ? AND risk = ? AND agent_id = ?
                AND last_sent > datetime('now', '-5 minutes')
                LIMIT 1
            """, (src_ip, risk, agent_id))
        else:
            c.execute("""
                SELECT 1 FROM alerts
                WHERE src_ip = ? AND risk = ?
                AND last_sent > datetime('now', '-5 minutes')
                LIMIT 1
            """, (src_ip, risk))
        return c.fetchone() is not None


def save_alert(src_ip, risk, agent_id=None, attack_type=None):
    """Registra que se envio una alerta."""
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("""
            INSERT INTO alerts (src_ip, risk, agent_id, attack_type)
            VALUES (?, ?, ?, ?)
        """, (src_ip, risk, agent_id, attack_type))
        conn.commit()


def get_all_logs(limit=100, offset=0):
    """Obtiene logs con paginacion."""
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT * FROM logs
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        """, (limit, offset))
        return c.fetchall()


def get_logs_count():
    """Obtiene el numero total de logs en la base de datos."""
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM logs")
        return c.fetchone()[0]


def get_stats_by_ip(limit=10):
    """Obtiene las IPs con mas eventos (top atacantes)."""
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT src_ip, COUNT(*) as count
            FROM logs
            WHERE src_ip IS NOT NULL
            GROUP BY src_ip
            ORDER BY count DESC
            LIMIT ?
        """, (limit,))
        return c.fetchall()


def get_stats_by_type():
    """Obtiene estadisticas agrupadas por tipo de ataque."""
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT attack_type, COUNT(*) as count
            FROM logs
            GROUP BY attack_type
            ORDER BY count DESC
        """)
        return c.fetchall()


def get_stats_by_risk():
    """Obtiene estadisticas agrupadas por nivel de riesgo."""
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT risk, COUNT(*) as count
            FROM logs
            GROUP BY risk
            ORDER BY risk DESC
        """)
        return c.fetchall()


def get_stats_by_source():
    """Obtiene estadisticas agrupadas por fuente de log."""
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT source, COUNT(*) as count
            FROM logs
            WHERE source IS NOT NULL
            GROUP BY source
            ORDER BY count DESC
        """)
        return c.fetchall()


def get_stats_by_agent():
    """Obtiene estadisticas agrupadas por agente."""
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT agent_id, COUNT(*) as count
            FROM logs
            GROUP BY agent_id
            ORDER BY count DESC
        """)
        return c.fetchall()


def get_stats_by_target_host():
    """Obtiene estadisticas de hosts mas atacados."""
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT target_host, agent_id, COUNT(*) as count
            FROM logs
            WHERE target_host IS NOT NULL
            GROUP BY target_host
            ORDER BY count DESC
        """)
        return c.fetchall()


def get_high_risk_logs(limit=50):
    """Obtiene los logs de mayor riesgo."""
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT * FROM logs
            WHERE risk >= 15
            ORDER BY risk DESC, timestamp DESC
            LIMIT ?
        """, (limit,))
        return c.fetchall()


def get_logs_by_agent(agent_id, limit=100):
    """Obtiene logs de un agente especifico."""
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT * FROM logs
            WHERE agent_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
        """, (agent_id, limit))
        return c.fetchall()


def get_logs_by_source(source, limit=100):
    """Obtiene logs de una fuente especifica."""
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT * FROM logs
            WHERE source = ?
            ORDER BY timestamp DESC
            LIMIT ?
        """, (source, limit))
        return c.fetchall()
