"""
Threat Correlation Module - Correlacion de amenazas multi-agente.

Este modulo analiza eventos de multiples agentes para detectar:
- Ataques coordinados
- IPs maliciosas vistas por multiple agentes
- Compromiso de cuentas (brute force + login exitoso)
- Patrones de ataque sofisticados

Implementa logica de correlacion basada en:
- IP origen
- Tipo de ataque
- Agentes que reportaron
- Secuencia temporal de eventos
"""

import json
import logging
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

from .db import get_connection

logger = logging.getLogger(__name__)


ATTACK_PATTERNS = {
    "brute_force": {
        "keywords": ["brute_force", "failed", "failure", "invalid", "incorrect"],
        "base_risk": 40,
        "description": "Intentos de fuerza bruta"
    },
    "ssh_attack": {
        "keywords": ["ssh", "login", "password"],
        "base_risk": 30,
        "description": "Ataque SSH"
    },
    "web_attack": {
        "keywords": ["http", "apache", "nginx", "GET", "POST"],
        "base_risk": 20,
        "description": "Ataque web"
    },
    "compromised": {
        "keywords": ["success_after_bruteforce", "login_success", "accepted"],
        "base_risk": 100,
        "description": "Cuenta comprometida"
    },
    "malware_download": {
        "keywords": ["suspicious_download", ".exe", ".dll", ".rar", ".zip", "malware download"],
        "base_risk": 75,
        "description": "Descarga de malware可疑"
    },
    "possible_c2": {
        "keywords": ["possible_c2", "c2", "beacon", "command and control"],
        "base_risk": 90,
        "description": "Trafico C2 detectado"
    },
    "pcap_analysis": {
        "keywords": ["pcap_analysis", "pcap-analyzer", "traffic analysis"],
        "base_risk": 60,
        "description": "Analisis PCAP de trafico"
    },
    "malware": {
        "keywords": ["malware", "malicious", "virus", "trojan"],
        "base_risk": 90,
        "description": "Posible malware"
    }
}


COMPROMISE_INDICATORS = [
    "ssh_login_success_after_bruteforce",
    "login_success_after_bruteforce",
    "brute_force_succeeded",
    "compromised",
    "account_cracked"
]


COORDINATION_THRESHOLD = 2


def init_threat_intel():
    """Crea la tabla threat_intel si no existe."""
    with get_connection() as conn:
        c = conn.cursor()
        
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


def analyze_event(src_ip: str, risk: int, agent_id: str, 
                  attack_type: str, target_host: str = None,
                  severity: str = None) -> Dict:
    """
    Analiza un evento y actualiza la inteligencia de amenazas.
    
    Solo correlaciona eventos con riesgo >= 15 (MEDIUM+).
    
    Args:
        src_ip: IP origen del ataque
        risk: Nivel de riesgo (0-100+)
        agent_id: ID del agente que reporta
        attack_type: Tipo de ataque
        target_host: Host objetivo
        severity: Severidad del evento
    
    Returns:
        Dict con informacion de la correlacion
    """
    if not src_ip:
        return {"status": "ignored", "reason": "no_ip"}
    
    if risk < 15:
        return {"status": "ignored", "reason": "low_risk", "risk": risk}
    
    correlation_result = {
        "ip": src_ip,
        "new": False,
        "is_coordinated": False,
        "is_compromised": False,
        "alert_level": "normal",
        "recommendations": []
    }
    
    try:
        with get_connection() as conn:
            c = conn.cursor()
            
            c.execute("SELECT * FROM threat_intel WHERE ip = ?", (src_ip,))
            existing = c.fetchone()
            
            if existing:
                attack_types = json.loads(existing["attack_types"]) if existing["attack_types"] else {}
                agent_ids = json.loads(existing["agent_ids"]) if existing["agent_ids"] else []
                
                if attack_type:
                    attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
                
                if agent_id not in agent_ids:
                    agent_ids.append(agent_id)
                
                agent_count = len(agent_ids)
                is_compromised = existing["is_compromised"] or _check_compromise(attack_type, risk)
                is_coordinated = agent_count >= COORDINATION_THRESHOLD
                
                c.execute("""
                    UPDATE threat_intel
                    SET last_seen = CURRENT_TIMESTAMP,
                        attack_types = ?,
                        agent_ids = ?,
                        agent_count = ?,
                        max_risk = MAX(max_risk, ?),
                        avg_risk = (avg_risk * event_count + ?) / (event_count + 1),
                        event_count = event_count + 1,
                        is_compromised = ?,
                        is_coordinated = ?
                    WHERE ip = ?
                """, (
                    json.dumps(attack_types),
                    json.dumps(agent_ids),
                    agent_count,
                    risk,
                    risk,
                    1 if is_compromised else 0,
                    1 if is_coordinated else 0,
                    src_ip
                ))
            else:
                attack_types = {attack_type: 1} if attack_type else {}
                agent_ids = [agent_id]
                is_compromised = _check_compromise(attack_type, risk)
                is_coordinated = False
                
                c.execute("""
                    INSERT INTO threat_intel (
                        ip, attack_types, agent_ids, agent_count,
                        max_risk, avg_risk, is_compromised, is_coordinated, event_count
                    )
                    VALUES (?, ?, ?, 1, ?, ?, ?, 0, 1)
                """, (
                    src_ip,
                    json.dumps(attack_types),
                    json.dumps(agent_ids),
                    risk,
                    risk,
                    1 if is_compromised else 0
                ))
                correlation_result["new"] = True
            
            conn.commit()
            
            correlation_result["is_coordinated"] = is_coordinated
            correlation_result["is_compromised"] = is_compromised
            
            if is_compromised:
                correlation_result["alert_level"] = "critical"
                correlation_result["recommendations"] = [
                    "Bloquear IP inmediatamente",
                    "Revisar logs de acceso",
                    "Cambiar credenciales comprometidas"
                ]
            elif is_coordinated:
                correlation_result["alert_level"] = "high"
                correlation_result["recommendations"] = [
                    "Monitorear actividad de esta IP",
                    "Revisar todos los agentes afectados"
                ]
            
            attack_type_lower = (attack_type or "").lower()
            if any(ind in attack_type_lower for ind in COMPROMISE_INDICATORS):
                correlation_result["alert_level"] = "critical"
                correlation_result["is_compromised"] = True
                if "Bloquear IP" not in correlation_result["recommendations"]:
                    correlation_result["recommendations"].insert(0, "CUENTA COMPROMETIDA - Revisar inmediatamente")
            
    except Exception as e:
        logger.error(f"Error en analyze_event: {e}")
        correlation_result["error"] = str(e)
    
    return correlation_result


def _check_compromise(attack_type: str, risk: int) -> bool:
    """Determina si el evento indica compromiso."""
    if risk >= 100:
        return True
    
    attack_type_lower = (attack_type or "").lower()
    if any(ind in attack_type_lower for ind in COMPROMISE_INDICATORS):
        return True
    
    return False


def get_threat_intel(ip: str = None, min_risk: int = 0, 
                     compromised_only: bool = False,
                     coordinated_only: bool = False,
                     limit: int = 50) -> List[Dict]:
    """
    Obtiene inteligencia de amenazas.
    
    Args:
        ip: Filtrar por IP especifica
        min_risk: Filtrar por riesgo minimo
        compromised_only: Solo amenazas comprometidas
        coordinated_only: Solo ataques coordinados
        limit: Limite de resultados
    
    Returns:
        Lista de amenazas
    """
    query = "SELECT * FROM threat_intel WHERE max_risk >= ?"
    params = [min_risk]
    
    if ip:
        query += " AND ip = ?"
        params.append(ip)
    
    if compromised_only:
        query += " AND is_compromised = 1"
    
    if coordinated_only:
        query += " AND is_coordinated = 1"
    
    query += " ORDER BY max_risk DESC, event_count DESC LIMIT ?"
    params.append(limit)
    
    with get_connection() as conn:
        c = conn.cursor()
        c.execute(query, params)
        rows = c.fetchall()
    
    results = []
    for row in rows:
        at_data = json.loads(row["attack_types"]) if row["attack_types"] else {}
        if isinstance(at_data, list):
            attack_types_display = at_data
        else:
            attack_types_display = [f"{k} ({v})" for k, v in sorted(at_data.items(), key=lambda x: -x[1])]
        
        results.append({
            "ip": row["ip"],
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
            "attack_types": attack_types_display,
            "attack_types_dict": at_data if isinstance(at_data, dict) else {},
            "agent_ids": json.loads(row["agent_ids"]) if row["agent_ids"] else [],
            "agent_count": row["agent_count"],
            "max_risk": row["max_risk"],
            "avg_risk": round(row["avg_risk"], 2) if row["avg_risk"] else 0,
            "is_compromised": bool(row["is_compromised"]),
            "is_coordinated": bool(row["is_coordinated"]),
            "recommendations": json.loads(row["recommendations"]) if row["recommendations"] else [],
            "event_count": row["event_count"]
        })
    
    return results


def get_coordinated_attacks() -> List[Dict]:
    """Obtiene ataques detectados en multiples agentes."""
    return get_threat_intel(coordinated_only=True, limit=100)


def get_compromised_indicators() -> List[Dict]:
    """Obtiene indicadores de compromiso (BREACH)."""
    return get_threat_intel(compromised_only=True, limit=100)


def get_threat_summary() -> Dict:
    """Obtiene resumen de amenazas."""
    with get_connection() as conn:
        c = conn.cursor()
        
        c.execute("SELECT COUNT(*) as total FROM threat_intel")
        total = c.fetchone()["total"]
        
        c.execute("SELECT COUNT(*) as count FROM threat_intel WHERE is_compromised = 1")
        compromised = c.fetchone()["count"]
        
        c.execute("SELECT COUNT(*) as count FROM threat_intel WHERE is_coordinated = 1")
        coordinated = c.fetchone()["count"]
        
        c.execute("SELECT COUNT(*) as count FROM threat_intel WHERE agent_count >= 2")
        multi_agent = c.fetchone()["count"]
        
        c.execute("SELECT AVG(max_risk) as avg_risk FROM threat_intel")
        avg_risk = c.fetchone()["avg_risk"] or 0
        
        c.execute("""
            SELECT ip, max_risk, agent_count, attack_types 
            FROM threat_intel 
            ORDER BY max_risk DESC, agent_count DESC 
            LIMIT 10
        """)
        top_threats = []
        for row in c.fetchall():
            top_threats.append({
                "ip": row["ip"],
                "max_risk": row["max_risk"],
                "agent_count": row["agent_count"],
                "attack_types": json.loads(row["attack_types"]) if row["attack_types"] else []
            })
    
    return {
        "total_threats": total,
        "compromised_count": compromised,
        "coordinated_count": coordinated,
        "multi_agent_count": multi_agent,
        "avg_risk": round(avg_risk, 2),
        "top_threats": top_threats
    }


def correlate_login_after_bruteforce(agent_id: str, src_ip: str) -> Dict:
    """
    Detecta si un login exitoso ocurre despues de brute force en otro agente.
    
    Esta es la correlacion mas critica: el atacante logro acceso
    desde otra fuente despues de un ataque de fuerza bruta.
    """
    result = {
        "detected": False,
        "alert": None,
        "other_agents": []
    }
    
    try:
        with get_connection() as conn:
            c = conn.cursor()
            
            c.execute("""
                SELECT DISTINCT agent_id, attack_type, risk, timestamp
                FROM logs
                WHERE src_ip = ? 
                AND agent_id != ?
                AND attack_type LIKE '%brute%'
                AND timestamp > datetime('now', '-1 hour')
                ORDER BY timestamp DESC
            """, (src_ip, agent_id))
            
            brute_force_events = c.fetchall()
            
            if brute_force_events:
                result["detected"] = True
                result["other_agents"] = [dict(row) for row in brute_force_events]
                result["alert"] = {
                    "type": "BREACH_DETECTED",
                    "message": f"Login exitoso desde IP {src_ip} despues de brute force en otros agentes",
                    "severity": "CRITICAL",
                    "recommendations": [
                        "Investigar como ingreso el atacante",
                        "Revisar vulnerabilidades en todos los servidores",
                        "Cambiar credenciales de todos los usuarios",
                        "Bloquear IP inmediatamente"
                    ]
                }
                
                update_threat_with_breach(src_ip, result["alert"])
    
    except Exception as e:
        logger.error(f"Error en correlate_login_after_bruteforce: {e}")
    
    return result


def update_threat_with_breach(ip: str, alert: Dict):
    """Actualiza una amenaza como breach confirmado."""
    try:
        with get_connection() as conn:
            c = conn.cursor()
            c.execute("""
                UPDATE threat_intel
                SET is_compromised = 1,
                    max_risk = 100,
                    recommendations = ?
                WHERE ip = ?
            """, (json.dumps(alert.get("recommendations", [])), ip))
            conn.commit()
    except Exception as e:
        logger.error(f"Error en update_threat_with_breach: {e}")


def get_agents_for_ip(ip: str) -> List[Dict]:
    """Obtiene todos los agentes que han visto una IP especifica."""
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT DISTINCT agent_id, attack_type, risk, timestamp, target_host
            FROM logs
            WHERE src_ip = ?
            ORDER BY timestamp DESC
        """, (ip,))
        
        return [dict(row) for row in c.fetchall()]


def cleanup_old_threats(days: int = 30):
    """Elimina inteligencia de amenazas antigua."""
    with get_connection() as conn:
        c = conn.cursor()
        c.execute("""
            DELETE FROM threat_intel
            WHERE last_seen < datetime('now', '-' || ? || '  days')
            AND is_compromised = 0
            AND is_coordinated = 0
        """, (days,))
        deleted = c.rowcount
        conn.commit()
        logger.info(f"Eliminadas {deleted} amenazas antiguas")
        return deleted


def re_correlate_all_threats():
    """
    Re-correlaciona todos los logs para actualizar threat_intel.

    Esta funcion debe llamarse periodicamente (ej: cada 24h) para:
    - Actualizar amenazas con nuevos eventos historicos
    - Corregir deduplicacion incorrecta
    - Recalcular indicadores de compromiso
    - Detectar ataques coordinados que no se detectaron en tiempo real
    """
    logger.info("Starting re-correlation of all logs...")

    try:
        with get_connection() as conn:
            c = conn.cursor()

            c.execute("""
                SELECT src_ip, agent_id, attack_type, risk, timestamp
                FROM logs
                WHERE risk >= 15
                ORDER BY timestamp ASC
            """)
            logs = c.fetchall()

            threats_by_ip = defaultdict(lambda: {
                "attack_types": defaultdict(int),
                "agent_ids": set(),
                "max_risk": 0,
                "total_risk": 0,
                "event_count": 0
            })

            for log in logs:
                src_ip = log["src_ip"]
                if not src_ip:
                    continue

                threat = threats_by_ip[src_ip]
                threat["attack_types"][log["attack_type"]] += 1
                threat["agent_ids"].add(log["agent_id"])
                threat["max_risk"] = max(threat["max_risk"], log["risk"])
                threat["total_risk"] += log["risk"]
                threat["event_count"] += 1

            updated_count = 0
            for ip, data in threats_by_ip.items():
                attack_types = dict(data["attack_types"])
                agent_ids = list(data["agent_ids"])
                agent_count = len(agent_ids)
                is_compromised = any(
                    at in COMPROMISE_INDICATORS
                    for at in attack_types.keys()
                ) or data["max_risk"] >= 100
                is_coordinated = agent_count >= COORDINATION_THRESHOLD

                avg_risk = data["total_risk"] / data["event_count"] if data["event_count"] > 0 else 0

                c.execute("""
                    INSERT INTO threat_intel (
                        ip, attack_types, agent_ids, agent_count,
                        max_risk, avg_risk, is_compromised, is_coordinated, event_count
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET
                        attack_types = excluded.attack_types,
                        agent_ids = excluded.agent_ids,
                        agent_count = excluded.agent_count,
                        max_risk = MAX(max_risk, excluded.max_risk),
                        avg_risk = excluded.avg_risk,
                        event_count = event_count + 1,
                        is_compromised = MAX(is_compromised, excluded.is_compromised),
                        is_coordinated = MAX(is_coordinated, excluded.is_coordinated),
                        last_seen = CURRENT_TIMESTAMP
                """, (
                    ip,
                    json.dumps(attack_types),
                    json.dumps(agent_ids),
                    agent_count,
                    data["max_risk"],
                    avg_risk,
                    1 if is_compromised else 0,
                    1 if is_coordinated else 0,
                    data["event_count"]
                ))

                if is_compromised or is_coordinated:
                    updated_count += 1

            conn.commit()
            logger.info(f"Re-correlation complete. {updated_count} threats updated.")

            return {
                "total_logs_processed": len(logs),
                "unique_ips": len(threats_by_ip),
                "threats_updated": updated_count
            }

    except Exception as e:
        logger.error(f"Error in re_correlate_all_threats: {e}")
        return {"error": str(e)}


def schedule_re_correlation(app, interval_hours: int = 24):
    """
    Programa re-correlacion periodica.

    Args:
        app: Instancia de Flask.
        interval_hours: Horas entre re-correlaciones.
    """
    import threading
    import time

    def run_scheduler():
        logger.info(f"Re-correlation scheduler started (every {interval_hours}h)")
        while True:
            time.sleep(interval_hours * 3600)
            try:
                with app.app_context():
                    logger.info("Running scheduled re-correlation...")
                    result = re_correlate_all_threats()
                    logger.info(f"Scheduled re-correlation complete: {result}")
            except Exception as e:
                logger.error(f"Error in scheduled re-correlation: {e}")

    scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
    scheduler_thread.start()
    logger.info(f"Re-correlation scheduled every {interval_hours} hours")