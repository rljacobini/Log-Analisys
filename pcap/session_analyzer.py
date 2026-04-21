# =============================================================================
# Session Analyzer - Analisis de sesiones de red
# =============================================================================
#
# Este modulo analiza sesiones TCP/UDP extrayendo de paquetes o logs Zeek.
# Detecta patrones anómalos y ataques basados en comportamiento de sesiones.
#
# Analisis realizados:
#   - Reconstruccion de sesiones TCP
#   - Analisis de flags TCP (SYN, FIN, RST, etc)
#   - Deteccion de escaneos de puertos
#   - Deteccion de fuerza bruta
#   - Calculo de metricas de sesion
#
# Uso:
#   from pcap.session_analyzer import SessionAnalyzer
#
#   analyzer = SessionAnalyzer(packets)
#   sessions = analyzer.build_sessions()
#   attacks = analyzer.detect_port_scans()
#
# =============================================================================

import logging
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger(__name__)


# =============================================================================
# Constantes
# =============================================================================

TCP_FLAG_SYN = 0x02
TCP_FLAG_SYN_ACK = 0x12
TCP_FLAG_ACK = 0x10
TCP_FLAG_FIN = 0x01
TCP_FLAG_FIN_ACK = 0x11
TCP_FLAG_RST = 0x04
TCP_FLAG_RST_ACK = 0x14
TCP_FLAG_PSH = 0x08
TCP_FLAG_URG = 0x20

CONN_STATE_SF = "SF"  # Normal
CONN_STATE_REJ = "REJ"  # Refused
CONN_STATE_SHR = "SHR"  # RST from responder
CONN_STATE_SHO = "SHO"  # RST from originator
CONN_STATE_SF = "SF"  # Normal (duplicate check)


@dataclass
class SessionStats:
    """Estadisticas de una sesion."""
    session_key: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    duration: float = 0.0
    packet_count: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    syn_count: int = 0
    synack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    window_min: int = 0
    window_max: int = 0
    window_avg: float = 0.0
    retransmits: int = 0
    out_of_order: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    packets: List = field(default_factory=list)


@dataclass
class AttackEvent:
    """Evento de ataque detectado."""
    attack_type: str
    src_ip: str
    dst_ip: str
    dst_port: int = 0
    severity: str = "MEDIUM"
    risk: int = 25
    description: str = ""
    details: Dict = field(default_factory=dict)


# =============================================================================
# Clase Session Analyzer
# =============================================================================

class SessionAnalyzer:
    """Analizador de sesiones de red."""

    def __init__(self, packets: List = None):
        self.packets = packets or []
        self.sessions: Dict[str, SessionStats] = {}
        self.connection_states: Dict[str, str] = {}

    @staticmethod
    def _make_session_key(src_ip: str, src_port: int, dst_ip: str, dst_port: int,
                          protocol: str = "tcp") -> str:
        """Crea clave unica para sesion."""
        return f"{src_ip}:{src_port}->{dst_ip}:{dst_port}:{protocol}"

    def build_sessions(self) -> Dict[str, SessionStats]:
        """Construye diccionario de sesiones desde paquetes."""
        self.sessions = {}
        port_scan_sessions = defaultdict(set)

        for packet in self.packets:
            if packet.protocol not in ("tcp", "udp"):
                continue

            key = self._make_session_key(
                packet.ip_src,
                packet.src_port,
                packet.ip_dst,
                packet.dst_port,
                packet.protocol
            )

            reverse_key = self._make_session_key(
                packet.ip_dst,
                packet.dst_port,
                packet.ip_src,
                packet.src_port,
                packet.protocol
            )

            if key not in self.sessions and reverse_key not in self.sessions:
                self.sessions[key] = SessionStats(
                    session_key=key,
                    src_ip=packet.ip_src,
                    dst_ip=packet.ip_dst,
                    src_port=packet.src_port,
                    dst_port=packet.dst_port,
                    protocol=packet.protocol,
                    start_time=packet.timestamp
                )

            target_key = key if key in self.sessions else reverse_key
            session = self.sessions[target_key]

            session.packet_count += 1

            if packet.ip_src == session.src_ip:
                session.packets_sent += 1
                session.bytes_sent += packet.captured_length
            else:
                session.packets_received += 1
                session.bytes_received += packet.captured_length

            if packet.protocol == "tcp":
                flags = packet.tcp_flags

                if flags & TCP_FLAG_SYN:
                    session.syn_count += 1
                if flags & TCP_FLAG_SYN and flags & TCP_FLAG_ACK:
                    session.synack_count += 1
                if flags & TCP_FLAG_FIN:
                    session.fin_count += 1
                if flags & TCP_FLAG_RST:
                    session.rst_count += 1
                if flags & TCP_FLAG_PSH:
                    session.psh_count += 1

                if session.window_min == 0 or packet.tcp_window < session.window_min:
                    session.window_min = packet.tcp_window
                if packet.tcp_window > session.window_max:
                    session.window_max = packet.tcp_window

            session.end_time = packet.timestamp
            session.duration = session.end_time - session.start_time

        for key, session in self.sessions.items():
            if session.packets_received > 0:
                session.window_avg = (session.window_min + session.window_max) / 2

        logger.info(f"Construidas {len(self.sessions)} sesiones")
        return self.sessions

    def build_sessions_from_zeek(self, connections) -> Dict[str, SessionStats]:
        """Construye sesiones desde conexiones Zeek."""
        self.sessions = {}

        for conn in connections:
            key = self._make_session_key(
                conn.orig_ip,
                conn.orig_port,
                conn.resp_ip,
                conn.resp_port,
                conn.proto.lower()
            )

            self.sessions[key] = SessionStats(
                session_key=key,
                src_ip=conn.orig_ip,
                dst_ip=conn.resp_ip,
                src_port=conn.orig_port,
                dst_port=conn.resp_port,
                protocol=conn.proto.lower(),
                duration=conn.duration,
                packet_count=conn.orig_pkts + conn.resp_pkts,
                bytes_sent=conn.orig_bytes,
                bytes_received=conn.resp_bytes,
                start_time=0.0
            )

        return self.sessions

    def analyze_tcp_flags(self, session_key: str = None) -> Dict[str, List[int]]:
        """Analiza flags TCP de una sesion o todas."""
        results = {}

        sessions_to_analyze = (
            {session_key: self.sessions[session_key]} if session_key and session_key in self.sessions
            else self.sessions
        )

        for key, session in sessions_to_analyze.items():
            if session.protocol != "tcp":
                continue

            results[key] = {
                "syn": session.syn_count,
                "synack": session.synack_count,
                "fin": session.fin_count,
                "rst": session.rst_count,
                "psh": session.psh_count
            }

        return results

    def detect_port_scans(self, threshold: int = 20) -> List[AttackEvent]:
        """Detecta escaneos de puertos."""
        attacks = []
        dst_port_counts = defaultdict(lambda: {"ips": set(), "count": 0})

        for packet in self.packets:
            if packet.dst_port > 0:
                dst_port_counts[packet.dst_port]["ips"].add(packet.ip_src)
                dst_port_counts[packet.dst_port]["count"] += 1

        for port, data in dst_port_counts.items():
            if data["count"] >= threshold and len(data["ips"]) == 1:
                ip = list(data["ips"])[0]
                unique_dsts = set()

                for p in self.packets:
                    if p.ip_src == ip and p.dst_port > 0:
                        unique_dsts.add(p.ip_dst)

                if len(unique_dsts) >= 1:
                    attacks.append(AttackEvent(
                        attack_type="port_scan",
                        src_ip=ip,
                        dst_ip=list(unique_dsts)[0],
                        dst_port=port,
                        severity="HIGH",
                        risk=40,
                        description=f"Port scan detected: {data['count']} puertos escaneados",
                        details={
                            "scanned_ports": data["count"],
                            "target_port": port,
                            "threshold": threshold
                        }
                    ))

        logger.info(f"Detectados {len(attacks)} escaneos de puertos")
        return attacks

    def detect_syn_flood(self, threshold: int = 50, window_seconds: float = 60.0) -> List[AttackEvent]:
        """Detecta inundacion SYN (DoS)."""
        attacks = []
        syn_counts = defaultdict(int)
        syn_times = defaultdict(list)

        for packet in self.packets:
            if packet.protocol != "tcp":
                continue

            flags = packet.tcp_flags
            if flags & TCP_FLAG_SYN and not (flags & TCP_FLAG_ACK):
                syn_counts[packet.ip_src] += 1
                syn_times[packet.ip_src].append(packet.timestamp)

        for ip, count in syn_counts.items():
            if count >= threshold:
                time_span = max(syn_times[ip]) - min(syn_times[ip]) if syn_times[ip] else 0
                if time_span <= window_seconds:
                    attacks.append(AttackEvent(
                        attack_type="syn_flood",
                        src_ip=ip,
                        severity="CRITICAL",
                        risk=70,
                        description=f"SYN flood detectado: {count} SYN en {time_span:.1f}s",
                        details={
                            "syn_count": count,
                            "time_window": time_span,
                            "threshold": threshold
                        }
                    ))

        logger.info(f"Detectados {len(attacks)} eventos SYN flood")
        return attacks

    def detect_brute_force(self, port: int = 22, threshold: int = 5,
                     window_seconds: float = 60.0) -> List[AttackEvent]:
        """Detecta ataques de fuerza bruta en SSH/FTP."""
        attacks = []
        attempt_counts = defaultdict(list)

        for packet in self.packets:
            if packet.protocol == "tcp" and packet.dst_port == port:
                attempt_counts[packet.ip_src].append(packet.timestamp)

        for ip, timestamps in attempt_counts.items():
            if len(timestamps) >= threshold:
                recent_attempts = [ts for ts in timestamps if ts >= max(timestamps) - window_seconds]
                if len(recent_attempts) >= threshold:
                    attacks.append(AttackEvent(
                        attack_type="brute_force",
                        src_ip=ip,
                        dst_port=port,
                        severity="HIGH",
                        risk=50,
                        description=f"Fuerza bruta detectada en puerto {port}: {len(recent_attempts)} intentos",
                        details={
                            "attempts": len(recent_attempts),
                            "port": port,
                            "threshold": threshold
                        }
                    ))

        logger.info(f"Detectadas {len(attacks)} tentativas de fuerza bruta")
        return attacks

    def detect_anomalies(self) -> List[AttackEvent]:
        """Detecta anomalias en sesiones."""
        attacks = []

        for key, session in self.sessions.items():
            if session.protocol != "tcp":
                continue

            if session.syn_count > 0 and session.synack_count == 0:
                attacks.append(AttackEvent(
                    attack_type="half_open_scan",
                    src_ip=session.src_ip,
                    dst_ip=session.dst_ip,
                    dst_port=session.dst_port,
                    severity="MEDIUM",
                    risk=30,
                    description="SYN sin respuesta (half-open scan)",
                    details={"session": key}
                ))

            if session.rst_count > 3:
                attacks.append(AttackEvent(
                    attack_type="rst_flood",
                    src_ip=session.src_ip,
                    dst_ip=session.dst_ip,
                    dst_port=session.dst_port,
                    severity="MEDIUM",
                    risk=30,
                    description=f"Muchas conexiones RST: {session.rst_count}",
                    details={"rst_count": session.rst_count}
                ))

            if session.duration > 0 and session.packet_count / session.duration > 1000:
                attacks.append(AttackEvent(
                    attack_type="high_volume",
                    src_ip=session.src_ip,
                    dst_ip=session.dst_ip,
                    dst_port=session.dst_port,
                    severity="LOW",
                    risk=15,
                    description=f"Alto volumen: {session.packet_count} paquetes en {session.duration:.1f}s",
                    details={
                        "packet_count": session.packet_count,
                        "duration": session.duration
                    }
                ))

        logger.info(f"Detectadas {len(attacks)} anomalias")
        return attacks

    def get_top_talkers(self, limit: int = 10) -> List[Dict]:
        """Obtiene las sesiones con mas trafico."""
        session_list = list(self.sessions.values())
        session_list.sort(key=lambda s: s.bytes_sent + s.bytes_received, reverse=True)

        return [
            {
                "session": s.session_key,
                "ip": s.src_ip,
                "packets": s.packet_count,
                "bytes": s.bytes_sent + s.bytes_received,
                "duration": s.duration
            }
            for s in session_list[:limit]
        ]

    def get_connection_summary(self) -> Dict:
        """Obtiene resumen de conexiones."""
        total_packets = sum(s.packet_count for s in self.sessions.values())
        total_bytes = sum(s.bytes_sent + s.bytes_received for s in self.sessions.values())
        total_duration = sum(s.duration for s in self.sessions.values())

        unique_ips = set()
        unique_ports = set()

        for s in self.sessions.values():
            unique_ips.add(s.src_ip)
            unique_ips.add(s.dst_ip)
            unique_ports.add(s.dst_port)

        return {
            "total_sessions": len(self.sessions),
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "total_duration": total_duration,
            "unique_ips": len(unique_ips),
            "unique_ports": len(unique_ports),
            "tcp_sessions": sum(1 for s in self.sessions.values() if s.protocol == "tcp"),
            "udp_sessions": sum(1 for s in self.sessions.values() if s.protocol == "udp")
        }

    def detect_all_attacks(self) -> List[AttackEvent]:
        """Ejecuta todas las detecciones."""
        all_attacks = []

        all_attacks.extend(self.detect_port_scans())
        all_attacks.extend(self.detect_syn_flood())
        all_attacks.extend(self.detect_brute_force())
        all_attacks.extend(self.detect_anomalies())

        return all_attacks